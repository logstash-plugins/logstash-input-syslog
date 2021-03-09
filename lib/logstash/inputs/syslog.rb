# encoding: utf-8
require "date"
require "socket"
require "concurrent/array"
require "logstash/filters/grok"
require "logstash/filters/date"
require "logstash/inputs/base"
require "logstash/namespace"
require 'logstash/plugin_mixins/ecs_compatibility_support'
require "stud/interval"

# Read syslog messages as events over the network.
#
# This input is a good choice if you already use syslog today.
# It is also a good choice if you want to receive logs from
# appliances and network devices where you cannot run your own
# log collector.
#
# Of course, 'syslog' is a very muddy term. This input only supports `RFC3164`
# syslog with some small modifications. The date format is allowed to be
# `RFC3164` style or `ISO8601`. Otherwise the rest of `RFC3164` must be obeyed.
# If you do not use `RFC3164`, do not use this input.
#
# For more information see the http://www.ietf.org/rfc/rfc3164.txt[RFC3164 page].
#
# Note: This input will start listeners on both TCP and UDP.
#
class LogStash::Inputs::Syslog < LogStash::Inputs::Base
  include LogStash::PluginMixins::ECSCompatibilitySupport(:disabled, :v1)

  config_name "syslog"

  default :codec, "plain"

  # The address to listen on.
  config :host, :validate => :string, :default => "0.0.0.0"

  # The port to listen on. Remember that ports less than 1024 (privileged
  # ports) may require root to use.
  config :port, :validate => :number, :default => 514

  # Use custom post-codec processing field (e.g. syslog, after cef codec
  # processing) instead of the default `message` field
  config :syslog_field, :validate => :string, :default => "message"

  # Set custom grok pattern to parse the syslog, in case the format differs
  # from the defined standard.  This is common in security and other appliances
  config :grok_pattern, :validate => :string

  # Proxy protocol support, only v1 is supported at this time
  # http://www.haproxy.org/download/1.5/doc/proxy-protocol.txt
  config :proxy_protocol, :validate => :boolean, :default => false

  # Use label parsing for severity and facility levels.
  config :use_labels, :validate => :boolean, :default => true

  # Labels for facility levels. These are defined in RFC3164.
  config :facility_labels, :validate => :array, :default => [ "kernel", "user-level", "mail", "system", "security/authorization", "syslogd", "line printer", "network news", "UUCP", "clock", "security/authorization", "FTP", "NTP", "log audit", "log alert", "clock", "local0", "local1", "local2", "local3", "local4", "local5", "local6", "local7" ]

  # Labels for severity levels. These are defined in RFC3164.
  config :severity_labels, :validate => :array, :default => [ "Emergency" , "Alert", "Critical", "Error", "Warning", "Notice", "Informational", "Debug" ]

  # Specify a time zone canonical ID to be used for date parsing.
  # The valid IDs are listed on the [Joda.org available time zones page](http://joda-time.sourceforge.net/timezones.html).
  # This is useful in case the time zone cannot be extracted from the value, and is not the platform default.
  # If this is not specified the platform default will be used.
  # Canonical ID is good as it takes care of daylight saving time for you
  # For example, `America/Los_Angeles` or `Europe/France` are valid IDs.
  config :timezone, :validate => :string

  # Specify a locale to be used for date parsing using either IETF-BCP47 or POSIX language tag.
  # Simple examples are `en`,`en-US` for BCP47 or `en_US` for POSIX.
  # If not specified, the platform default will be used.
  #
  # The locale is mostly necessary to be set for parsing month names (pattern with MMM) and
  # weekday names (pattern with EEE).
  #
  config :locale, :validate => :string

  def initialize(*params)
    super

    @priority_key = ecs_select[disabled:'priority', v1:'[log][syslog][priority]']
    @facility_key = ecs_select[disabled:'facility', v1:'[log][syslog][facility][code]']
    @severity_key = ecs_select[disabled:'severity', v1:'[log][syslog][severity][code]']

    @facility_label_key = ecs_select[disabled:'facility_label', v1:'[log][syslog][facility][name]']
    @severity_label_key = ecs_select[disabled:'severity_label', v1:'[log][syslog][severity][name]']

    @host_key = ecs_select[disabled:'host', v1:'[host][ip]']

    @grok_pattern ||= ecs_select[
        disabled:"<%{POSINT:#{@priority_key}}>%{SYSLOGLINE}",
        v1:"<%{POSINT:#{@priority_key}:int}>%{SYSLOGLINE}"
    ]

    @grok_filter = LogStash::Filters::Grok.new(
        "overwrite" => @syslog_field,
        "match" => { @syslog_field => @grok_pattern },
        "tag_on_failure" => ["_grokparsefailure_sysloginput"],
        "ecs_compatibility" => ecs_compatibility # use ecs-compliant patterns
    )

    @grok_filter_exec = ecs_select[
        disabled: -> (event) { @grok_filter.filter(event) },
        v1: -> (event) {
          event.set('[event][original]', event.get(@syslog_field))
          @grok_filter.filter(event)
        }
    ]

    @date_filter = LogStash::Filters::Date.new(
        "match" => [ "timestamp", "MMM dd HH:mm:ss", "MMM  d HH:mm:ss", "MMM d HH:mm:ss", "ISO8601"],
        "locale" => @locale,
        "timezone" => @timezone,
    )

    @date_filter_exec = ecs_select[
        disabled: -> (event) {
          # in legacy (non-ecs) mode we used to match (SYSLOGBASE2) timestamp into two fields
          event.set("timestamp", event.get("timestamp8601")) if event.include?("timestamp8601")
          @date_filter.filter(event)
        },
        v1: -> (event) {
          @date_filter.filter(event)
          event.remove('timestamp')
        }
    ]
  end

  def register
    @metric_errors = metric.namespace(:errors)

    @grok_filter.register
    @date_filter.register

    @tcp_sockets = Concurrent::Array.new
    @tcp = @udp = nil
  end # def register

  private

  def run(output_queue)
    udp_thr = Thread.new(output_queue) do |output_queue|
      server(:udp, output_queue)
    end

    tcp_thr = Thread.new(output_queue) do |output_queue|
      server(:tcp, output_queue)
    end

    # If we exit and we're the only input, the agent will think no inputs
    # are running and initiate a shutdown.
    udp_thr.join
    tcp_thr.join
  end # def run
  public :run

  # server call the specified protocol listener and basically restarts on
  # any listener uncatched exception
  #
  # @param protocol [Symbol] either :udp or :tcp
  # @param output_queue [Queue] the pipeline input to filters queue
  def server(protocol, output_queue)
    self.send("#{protocol}_listener", output_queue)
  rescue => e
    if !stop?
      @logger.warn("syslog listener died", :protocol => protocol, :address => "#{@host}:#{@port}", :exception => e, :backtrace => e.backtrace)
      @metric_errors.increment(:listener)
      Stud.stoppable_sleep(5) { stop? }
      retry
    end
  end

  # udp_listener creates the udp socket and continously read from it.
  # upon exception the socket will be closed and the exception bubbled
  # in the server which will restart the listener
  def udp_listener(output_queue)
    @logger.info("Starting syslog udp listener", :address => "#{@host}:#{@port}")

    @udp.close if @udp
    @udp = UDPSocket.new (IPAddr.new(@host).ipv6? rescue nil) ? Socket::AF_INET6 : Socket::AF_INET
    @udp.do_not_reverse_lookup = true
    @udp.bind(@host, @port)

    while !stop?
      payload, client = @udp.recvfrom(65507)
      metric.increment(:messages_received)
      decode(client[3], output_queue, payload)
    end
  ensure
    close_udp
  end # def udp_listener

  # tcp_listener accepts tcp connections and creates a new tcp_receiver thread
  # for each accepted socket.
  # upon exception all tcp sockets will be closed and the exception bubbled
  # in the server which will restart the listener.
  def tcp_listener(output_queue)
    @logger.info("Starting syslog tcp listener", :address => "#{@host}:#{@port}")
    @tcp = TCPServer.new(@host, @port)
    @tcp.do_not_reverse_lookup = true

    while !stop?
      socket = @tcp.accept
      @tcp_sockets << socket
      metric.increment(:connections)

      Thread.new(output_queue, socket) do |output_queue, socket|
        tcp_receiver(output_queue, socket)
      end
    end
  ensure
    close_tcp
  end # def tcp_listener

  # tcp_receiver is executed in a thread, any uncatched exception will be bubbled up to the
  # tcp server thread and all tcp connections will be closed and the listener restarted.
  def tcp_receiver(output_queue, socket)
    ip, port = socket.peeraddr[3], socket.peeraddr[1]
    first_read = true
    @logger.info("new connection", :client => "#{ip}:#{port}")
    LogStash::Util::set_thread_name("input|syslog|tcp|#{ip}:#{port}}")

    socket.each do |line|
      metric.increment(:messages_received)
      if @proxy_protocol && first_read
        first_read = false
        pp_info = line.split(/\s/)
        # PROXY proto clientip proxyip clientport proxyport
        if pp_info[0] != "PROXY"
          @logger.error("invalid proxy protocol header label", :hdr => line)
          raise IOError
        else
          # would be nice to log the proxy host and port data as well, but minimizing changes
          ip = pp_info[2]
          port = pp_info[3]
          next
        end
      end
      decode(ip, output_queue, line)
    end
  rescue Errno::ECONNRESET
    # swallow connection reset exceptions to avoid bubling up the tcp_listener & server
    logger.info("connection reset", :client => "#{ip}:#{port}")
  rescue Errno::EBADF
    # swallow connection closed exceptions to avoid bubling up the tcp_listener & server
    logger.info("connection closed", :client => "#{ip}:#{port}")
  rescue IOError => e
    # swallow connection closed exceptions to avoid bubling up the tcp_listener & server
    raise(e) unless socket.closed? && e.message.to_s.include?("closed")
    logger.info("connection error:", :exception => e.class, :message => e.message)
  ensure
    @tcp_sockets.delete(socket)
    socket.close rescue log_and_squash(:close_tcp_receiver_socket)
  end

  def decode(ip, output_queue, data)
    @codec.decode(data) do |event|
      decorate(event)
      event.set(@host_key, ip)
      syslog_relay(event)
      output_queue << event
      metric.increment(:events)
    end
  rescue => e
    # swallow and log all decoding exceptions, these will never be socket related
    @logger.error("Error decoding data", :data => data.inspect, :exception => e.class, :message => e.message, :backtrace => e.backtrace)
    @metric_errors.increment(:decoding)
  end

  # @see LogStash::Plugin#close
  def stop
    close_udp
    close_tcp
  end
  public :stop

  def close_udp
    if @udp
      @udp.close_read rescue log_and_squash(:close_udp_read)
      @udp.close_write rescue log_and_squash(:close_udp_write)
    end
    @udp = nil
  end

  # Helper for inline rescues, which logs the exception at "DEBUG" level and returns nil.
  #
  # Instead of:
  # ~~~ ruby
  #.  foo rescue nil
  # ~~~
  # Do:
  # ~~~ ruby
  #.  foo rescue log_and_squash(:foo)
  # ~~~
  def log_and_squash(label)
    $! && logger.debug("#{label} failed:", :exception => $!.class, :message => $!.message)
    nil
  end

  def close_tcp
    # If we somehow have this left open, close it.
    @tcp_sockets.each do |socket|
      socket.close rescue log_and_squash(:close_tcp_socket)
    end
    @tcp.close if @tcp rescue log_and_squash(:close_tcp)
    @tcp = nil
  end

  # Following RFC3164 where sane, we'll try to parse a received message
  # as if you were relaying a syslog message to it.
  # If the message cannot be recognized (see @grok_filter), we'll
  # treat it like the whole event["message"] is correct and try to fill
  # the missing pieces (host, priority, etc)
  def syslog_relay(event)
    @grok_filter_exec.(event)

    if event.get("tags").nil? || !event.get("tags").include?(@grok_filter.tag_on_failure)
      # Per RFC3164, priority = (facility * 8) + severity
      #                       = (facility << 3) & (severity)
      priority = event.get(@priority_key).to_i rescue 13
      set_priority event, priority

      @date_filter_exec.(event)

    else
      @logger.debug? && @logger.debug("un-matched syslog message", :message => event.get("message"))

      # RFC3164 says unknown messages get pri=13
      set_priority event, 13
      metric.increment(:unknown_messages)
    end

    # Apply severity and facility metadata if use_labels => true
    set_labels(event) if @use_labels
  end # def syslog_relay
  public :syslog_relay

  def set_priority(event, priority)
    severity = priority & 7 # 7 is 111 (3 bits)
    facility = priority >> 3
    event.set(@priority_key, priority)
    event.set(@severity_key, severity)
    event.set(@facility_key, facility)
  end

  def set_labels(event)
    facility_number = event.get(@facility_key)
    severity_number = event.get(@severity_key)

    facility_label = @facility_labels[facility_number]
    event.set(@facility_label_key, facility_label) if facility_label

    severity_label = @severity_labels[severity_number]
    event.set(@severity_label_key, severity_label) if severity_label
  end

end # class LogStash::Inputs::Syslog
