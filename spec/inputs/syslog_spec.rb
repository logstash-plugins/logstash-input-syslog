# encoding: utf-8
require "logstash/devutils/rspec/spec_helper"
require "logstash/devutils/rspec/shared_examples"

require 'logstash/plugin_mixins/ecs_compatibility_support/spec_helper'

# running the grok code outside a logstash package means
# LOGSTASH_HOME will not be defined, so let's set it here
# before requiring the grok filter
unless LogStash::Environment.const_defined?(:LOGSTASH_HOME)
  LogStash::Environment::LOGSTASH_HOME = File.expand_path("../../", __FILE__)
end

# temporary fix to have the spec pass for an urgen mass-publish requirement.
# cut & pasted from the same tmp fix in the grok spec
# see https://github.com/logstash-plugins/logstash-filter-grok/issues/72
# this needs to be refactored and properly fixed
module LogStash::Environment
  # also :pattern_path method must exist so we define it too
  unless self.method_defined?(:pattern_path)
    def pattern_path(path)
      ::File.join(LOGSTASH_HOME, "patterns", path)
    end
  end
end

require "logstash/inputs/syslog"
require "logstash/codecs/cef"
require "logstash/event"
require "stud/try"
require "socket"

describe LogStash::Inputs::Syslog do
  SYSLOG_LINE = "<164>Oct 26 15:19:25 1.2.3.4 %ASA-4-106023: Deny udp src DRAC:10.1.2.3/43434 dst outside:192.168.0.1/53 by access-group \"acl_drac\" [0x0, 0x0]"

  context 'ECS common behavior', :ecs_compatibility_support do
    ecs_compatibility_matrix(:disabled, :v1, :v8 => :v1) do |ecs_select|
      let(:priority_key) { ecs_select[disabled:'priority', v1:'[log][syslog][priority]'] }
      let(:facility_key) { ecs_select[disabled:'facility', v1:'[log][syslog][facility][code]'] }
      let(:severity_key) { ecs_select[disabled:'severity', v1:'[log][syslog][severity][code]'] }
      let(:host_key) { ecs_select[disabled:'host', v1:'[host][ip]'] }

      before(:each) do
        allow_any_instance_of(described_class).to receive(:ecs_compatibility).and_return(ecs_compatibility)
      end

      it "should properly handle priority, severity and facilities" do
        skip_if_stack_known_issue
        port = 5511
        event_count = 10
        conf = <<-CONFIG
          input {
            syslog {
              type => "blah"
              port => #{port}
            }
          }
        CONFIG

        events = input(conf) do |pipeline, queue|
          socket = Stud.try(5.times) { TCPSocket.new("127.0.0.1", port) }
          event_count.times do |i|
            socket.puts(SYSLOG_LINE)
          end
          socket.close

          event_count.times.collect { queue.pop }
        end

        expect( events.length ).to eql event_count
        events.each do |event|
          expect( event.get(priority_key) ).to eql 164
          expect( event.get(severity_key) ).to eql 4
          expect( event.get(facility_key) ).to eql 20
        end
      end

      it "should properly PROXY protocol v1" do
        skip_if_stack_known_issue
        port = 5511
        event_count = 10
        conf = <<-CONFIG
          input {
            syslog {
              type => "blah"
              port => #{port}
              proxy_protocol => true
            }
          }
        CONFIG

        events = input(conf) do |pipeline, queue|
          socket = Stud.try(5.times) { TCPSocket.new("127.0.0.1", port) }
          socket.puts("PROXY TCP4 1.2.3.4 5.6.7.8 1234 5678\r\n")
          socket.flush
          event_count.times do |i|
            socket.puts(SYSLOG_LINE)
          end
          socket.close

          event_count.times.collect { queue.pop }
        end

        expect( events.length ).to eql event_count
        events.each do |event|
          expect( event.get(priority_key) ).to eql 164
          expect( event.get(severity_key) ).to eql 4
          expect( event.get(facility_key) ).to eql 20
          expect( event.get(host_key) ).to eql "1.2.3.4"
        end
      end

      context 'grok' do
        it "should add unique tag when grok parsing fails with live syslog input" do
          skip_if_stack_known_issue
          port = 5511
          event_count = 10
          conf = <<-CONFIG
            input {
              syslog {
                type => "blah"
                port => #{port}
              }
            }
          CONFIG
          events = input(conf) do |pipeline, queue|
            socket = Stud.try(5.times) { TCPSocket.new("127.0.0.1", port) }
            event_count.times do |i|
              socket.puts("message which causes the a grok parse failure")
            end
            socket.close
            event_count.times.collect { queue.pop }
          end
          expect( events.length ).to eql event_count
          event_count.times do |i|
            expect( events[i].get("tags") ).to eql ["_grokparsefailure_sysloginput"]
          end
        end

        it "should add unique tag when grok parsing fails" do
          input = LogStash::Inputs::Syslog.new({})
          input.register

          # event which is not syslog should have a new tag
          event = LogStash::Event.new({ "message" => "hello world, this is not syslog RFC3164" })
          input.syslog_relay(event)
          expect( event.get("tags") ).to eql  ["_grokparsefailure_sysloginput"]

          syslog_event = LogStash::Event.new({ "message" => "<164>Oct 26 15:19:25 1.2.3.4 %ASA-4-106023: Deny udp src DRAC:10.1.2.3/43434" })
          input.syslog_relay(syslog_event)
          expect( syslog_event.get(priority_key) ).to eql 164
          expect( syslog_event.get(severity_key) ).to eql 4
          expect( syslog_event.get("tags") ).to be nil

          input.close
        end

        it "should properly handle a custom grok_pattern" do
          port = 5511
          event_count = 1
          custom_grok = "<%{POSINT:#{priority_key}}>%{SYSLOGTIMESTAMP:timestamp} atypical %{GREEDYDATA:message}"
          message_field = "This part constitutes the message field"
          timestamp = "Oct 26 15:19:25"
          custom_line = "<164>#{timestamp} atypical #{message_field}"

          conf = <<-CONFIG
            input {
              syslog {
                type => "blah"
                port => #{port}
                grok_pattern => "#{custom_grok}"
              }
            }
          CONFIG

          events = input(conf) do |pipeline, queue|
            socket = Stud.try(5.times) { TCPSocket.new("127.0.0.1", port) }
            event_count.times do |i|
              socket.puts(custom_line)
            end
            socket.close

            event_count.times.collect { queue.pop }
          end

          expect( events.length ).to eql event_count
          events.each do |event|
            expect( event.get(priority_key) ).to eql 164
            expect( event.get(severity_key) ).to eql 4
            expect( event.get(facility_key) ).to eql 20
            expect( event.get("message") ).to eql "#{message_field}\n"
            expect( event.get('timestamp') ).to eql timestamp if ecs_compatibility == :disabled
            expect( event.include?('timestamp') ).to be false if ecs_compatibility != :disabled
          end
        end

        it "should properly handle the cef codec with a custom grok_pattern" do
          port = 5511
          event_count = 1

          custom_grok = "<%{POSINT:#{priority_key}}>%{TIMESTAMP_ISO8601:timestamp} atypical %{GREEDYDATA:syslog_message}"
          timestamp = "2018-02-07T12:40:00.000Z"
          cef_message = "Description Omitted"
          syslog_message = "foo bar"
          syslog_message_envelope = "<134>#{timestamp} atypical #{syslog_message}"
          custom_line = "CEF:0|Company Name|Application Name|Application Version Number|632|Syslog Configuration Updated|3|src=192.168.0.1 suser=user@example.com target=TARGET msg=#{cef_message} syslog=#{syslog_message_envelope} KeyValueOne=kv1 KeyValueTwo=12345 "

          conf = <<-CONFIG
            input {
              syslog {
                port => #{port}
                syslog_field => "syslog"
                grok_pattern => "#{custom_grok}"
                codec => cef { ecs_compatibility => #{ ecs_compatibility } }
              }
            }
          CONFIG

          events = input(conf) do |pipeline, queue|
            socket = Stud.try(5.times) { TCPSocket.new("127.0.0.1", port) }
            event_count.times do |i|
              socket.puts(custom_line)
            end
            socket.close

            event_count.times.collect { queue.pop }
          end

          expect( events.length ).to eql event_count
          events.each do |event|
            expect( event.get(priority_key) ).to eql 134
            expect( event.get(severity_key) ).to eql 6
            expect( event.get(facility_key) ).to eql 16
            expect( event.get("message") ).to eql cef_message
            expect( event.get("syslog_message") ).to eql syslog_message
            expect( event.get('timestamp') ).to eql timestamp if ecs_compatibility == :disabled
            expect( event.include?('timestamp') ).to be false if ecs_compatibility != :disabled
          end
        end
      end

      context 'timestamp' do
        it "should properly handle locale and timezone" do
          port = 5511
          event_count = 10

          conf = <<-CONFIG
            input {
              syslog {
                type => "blah"
                port => #{port}
                locale => "en"
                timezone => "UTC"
              }
            }
          CONFIG

          events = input(conf) do |pipeline, queue|
            socket = Stud.try(5.times) { TCPSocket.new("127.0.0.1", port) }
            event_count.times do |i|
              socket.puts(SYSLOG_LINE)
            end
            socket.close

            event_count.times.collect { queue.pop }
          end

          expect( events.length ).to eql event_count
          events.each do |event|
            expect( event.get("@timestamp") ).to be_a_logstash_timestamp_equivalent_to("#{Time.now.year}-10-26T15:19:25Z")
          end
        end

        it "should properly handle no locale and no timezone" do
          port = 5511

          conf = <<-CONFIG
            input {
              syslog {
                type => "blah"
                port => #{port}
              }
            }
          CONFIG

          event = input(conf) do |pipeline, queue|
            socket = Stud.try(5.times) { TCPSocket.new("127.0.0.1", port) }
            socket.puts(SYSLOG_LINE)
            socket.close

            queue.pop
          end

          # chances platform timezone is not UTC, so parse without offset to create expectation
          equivalent_time = Time.parse("#{Time.now.year}-10-26T15:19:25")
          expect( event.get("@timestamp") ).to be_a_logstash_timestamp_equivalent_to(equivalent_time)
        end

        it "should support non UTC timezone" do
          input = LogStash::Inputs::Syslog.new({"timezone" => "-05:00"})
          input.register

          # event which is not syslog should have a new tag

          syslog_event = LogStash::Event.new({ "message" => "<164>Oct 26 15:19:25 1.2.3.4 %ASA-4-106023: Deny udp src DRAC:10.1.2.3/43434" })
          input.syslog_relay(syslog_event)

          expect( syslog_event.get("@timestamp") ).to be_a_logstash_timestamp_equivalent_to("#{Time.now.year}-10-26T20:19:25Z")

          input.close
        end
      end
    end
  end

  context 'ECS :v1 behavior', :ecs_compatibility_support do

    ecs_compatibility_matrix(:v1) do

      before(:each) do
        allow_any_instance_of(described_class).to receive(:ecs_compatibility).and_return(ecs_compatibility)
      end

      let(:event) do
        LogStash::Event.new("message" => "<164>Oct 26 15:19:25 1.2.3.4 a sample message")
      end

      subject { LogStash::Inputs::Syslog.new }

      before { subject.register }
      after { subject.close }

      it "should not have a timestamp field" do
        subject.syslog_relay(event)

        expect( event.to_hash.keys ).to_not include 'timestamp'
      end

      it "overwrites message" do
        subject.syslog_relay(event)

        expect( event.get('message') ).to eql 'a sample message'
      end

      it "keep original log message" do
        subject.syslog_relay(event)

        expect( event.get('[event][original]') ).to eql '<164>Oct 26 15:19:25 1.2.3.4 a sample message'
      end

      it "sets syslog priority and severity" do
        subject.syslog_relay(event)

        expect( event.get('log') ).to include 'syslog' => hash_including('priority' => 164)
        expect( event.get('log') ).to include 'syslog' => hash_including('severity' => { 'code' => 4, 'name' => 'Warning' })
      end

      it "sets service type" do
        subject.syslog_relay(event)

        expect( event.get('service') ).to include 'type' => 'system'
      end

      let(:queue) { Queue.new }

      let(:socket) do
        server = double('tcp-server')
        allow( subject ).to receive(:tcp_read_lines).and_yield("<133>Mar 11 08:44:43 precision kernel: [765135.424096] mce: CPU6: Package temperature/speed normal\n")
        allow( server ).to receive(:close)
        server
      end

      it "sets host IP" do
        expect( socket ).to receive(:peeraddr).and_return(["AF_INET", 514, "192.168.0.10", "192.168.0.10"])
        subject.send :tcp_receiver, queue, socket

        expect( queue.size ).to eql 1
        event = queue.pop
        expect( event.get('host') ).to eql 'hostname' => 'precision', 'ip' => '192.168.0.10'
      end
    end
  end

  context 'tcp receiver' do
    subject(:plugin) { LogStash::Inputs::Syslog.new }
    before { plugin.register }
    after { plugin.close }

    let(:queue) { Queue.new }
    let(:socket) do
      socket = double('tcp-socket')
      expect( socket ).to receive(:peeraddr).and_return(["AF_INET", 514, "192.168.0.10", "192.168.0.10"])
      socket
    end

    it 'should close connection when client sends EOF' do
      expect( socket ).to receive(:read_nonblock).and_raise(EOFError)
      expect( socket ).to receive(:close)
      allow( plugin.logger ).to receive(:info)

      plugin.send :tcp_receiver, queue, socket

      expect( plugin.logger ).to have_received(:info).with(/connection closed/, anything)
      expect( queue.size ).to eql 0
    end

    it 'should properly read partially received messages' do
      expect( socket ).to receive(:close)
      allow( plugin.codec ).to receive(:decode).and_call_original

      messages = ["<133>Mar 11 08:44:43 localhost message 2\n", "message 1\n", "<133>Mar 11 08:44:43 localhost ", ]
      allow( socket ).to receive(:read_nonblock).at_least(messages.size).times do
        msg = messages.pop
        raise EOFError unless msg
        msg
      end

      plugin.send :tcp_receiver, queue, socket

      expect( queue.size ).to eql 2
      expect( plugin.codec ).to have_received(:decode).with("<133>Mar 11 08:44:43 localhost message 1\n")
      expect( plugin.codec ).to have_received(:decode).with("<133>Mar 11 08:44:43 localhost message 2\n")
    end
  end


  it_behaves_like 'an interruptible input plugin' do
    let(:config) { { "port" => 5511 } }
  end

  private

  def skip_if_stack_known_issue
    skip 'elastic/logstash#11196 known LS 7.5 issue' if ENV['ELASTIC_STACK_VERSION'] && JRUBY_VERSION.eql?('9.2.8.0')
  end
end
