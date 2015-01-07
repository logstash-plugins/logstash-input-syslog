# encoding: utf-8
require "logstash/devutils/rspec/spec_helper"
require "logstash/inputs/syslog"
require "logstash/event"
require "stud/try"
require "socket"

describe "inputs/syslog" do
  SYSLOG_LINE = "<164>Oct 26 15:19:25 1.2.3.4 %ASA-4-106023: Deny udp src DRAC:10.1.2.3/43434 dst outside:192.168.0.1/53 by access-group \"acl_drac\" [0x0, 0x0]"

  describe "should properly handle priority, severity and facilities" do
    port = 5511
    event_count = 10

    config <<-CONFIG
      input {
        syslog {
          type => "blah"
          port => #{port}
        }
      }
    CONFIG

    input do |pipeline, queue|
      t = Thread.new { pipeline.run }
      sleep 0.1 while !pipeline.ready?

      socket = Stud.try(5.times) { TCPSocket.new("127.0.0.1", port) }
      event_count.times do |i|
        socket.puts(SYSLOG_LINE)
      end
      socket.close

      events = event_count.times.collect { queue.pop }

      # important to shutdown here before any assertion so that the pipeline + socket
      # cleanups are correctly done before any potential spec error that would result
      # in aborting execution and not doing the cleanup.
      pipeline.shutdown
      t.join

      insist { events.length } == event_count
      events.each do |event|
        insist { event["priority"] } == 164
        insist { event["severity"] } == 4
        insist { event["facility"] } == 20
      end
    end
  end

  describe "should add unique tag when grok parsing fails with live syslog input" do
    port = 5511
    event_count = 10

    config <<-CONFIG
      input {
        syslog {
          type => "blah"
          port => #{port}
        }
      }
    CONFIG

    input do |pipeline, queue|
      t = Thread.new { pipeline.run }
      sleep 0.1 while !pipeline.ready?

      socket = Stud.try(5.times) { TCPSocket.new("127.0.0.1", port) }
      event_count.times do |i|
        socket.puts("message which causes the a grok parse failure")
      end
      socket.close

      events = event_count.times.collect { queue.pop }

      # important to shutdown here before any assertion so that the pipeline + socket
      # cleanups are correctly done before any potential spec error that would result
      # in aborting execution and not doing the cleanup.
      pipeline.shutdown
      t.join

      insist { events.length } == event_count
      event_count.times do |i|
        insist { events[i]["tags"] } == ["_grokparsefailure_sysloginput"]
      end
    end
  end

  describe "should properly handle locale and timezone" do
    port = 5511
    event_count = 10

    config <<-CONFIG
      input {
        syslog {
          type => "blah"
          port => #{port}
          locale => "en"
          timezone => "UTC"
        }
      }
    CONFIG

    input do |pipeline, queue|
      t = Thread.new { pipeline.run }
      sleep 0.1 while !pipeline.ready?

      socket = Stud.try(5.times) { TCPSocket.new("127.0.0.1", port) }
      event_count.times do |i|
        socket.puts(SYSLOG_LINE)
      end
      socket.close

      events = event_count.times.collect { queue.pop }

      # important to shutdown here before any assertion so that the pipeline + socket
      # cleanups are correctly done before any potential spec error that would result
      # in aborting execution and not doing the cleanup.
      pipeline.shutdown
      t.join

      insist { events.length } == event_count
      events.each do |event|
        insist { event["@timestamp"].to_iso8601 } == "#{Time.now.year}-10-26T15:19:25.000Z"
      end
    end
  end

  describe "should properly handle no locale and no timezone" do
    port = 5511

    config <<-CONFIG
      input {
        syslog {
          type => "blah"
          port => #{port}
        }
      }
    CONFIG

    input do |pipeline, queue|
      t = Thread.new { pipeline.run }
      sleep 0.1 while !pipeline.ready?

      socket = Stud.try(5.times) { TCPSocket.new("127.0.0.1", port) }
      socket.puts(SYSLOG_LINE)
      socket.close

      event = queue.pop

      # important to shutdown here before any assertion so that the pipeline + socket
      # cleanups are correctly done before any potential spec error that would result
      # in aborting execution and not doing the cleanup.
      pipeline.shutdown
      t.join

      # chances platform timezone is not UTC so ignore the hours
      insist { event["@timestamp"].to_iso8601 } =~ /#{Time.now.year}-10-26T\d\d:19:25.000Z/
    end
  end

  it "should support non UTC timezone" do
    input = LogStash::Inputs::Syslog.new({"timezone" => "-05:00"})
    input.register

    # event which is not syslog should have a new tag

    syslog_event = LogStash::Event.new({ "message" => "<164>Oct 26 15:19:25 1.2.3.4 %ASA-4-106023: Deny udp src DRAC:10.1.2.3/43434" })
    input.syslog_relay(syslog_event)
    insist { syslog_event["@timestamp"].to_iso8601 } == "#{Time.now.year}-10-26T20:19:25.000Z"
  end

  it "should add unique tag when grok parsing fails" do
    input = LogStash::Inputs::Syslog.new({})
    input.register

    # event which is not syslog should have a new tag
    event = LogStash::Event.new({ "message" => "hello world, this is not syslog RFC3164" })
    input.syslog_relay(event)
    insist { event["tags"] } ==  ["_grokparsefailure_sysloginput"]

    syslog_event = LogStash::Event.new({ "message" => "<164>Oct 26 15:19:25 1.2.3.4 %ASA-4-106023: Deny udp src DRAC:10.1.2.3/43434" })
    input.syslog_relay(syslog_event)
    insist { syslog_event["priority"] } ==  164
    insist { syslog_event["severity"] } ==  4
    insist { syslog_event["tags"] } ==  nil
  end

end
