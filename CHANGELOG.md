## 3.7.0
  - Changed the TCP reading mode to use the non-blocking method [#75](https://github.com/logstash-plugins/logstash-input-syslog/pull/75)
    It fixes the high CPU usage when TCP clients do not properly disconnect/send EOF.
  - Fixed broken tests

## 3.6.0
  - Add support for ECS v8 as alias to v1 implementation [#68](https://github.com/logstash-plugins/logstash-input-syslog/pull/68)

## 3.5.0
  - Feat: ECS compatibility support [#63](https://github.com/logstash-plugins/logstash-input-syslog/pull/63)

## 3.4.5
  - Added support for listening on IPv6 addresses

## 3.4.4
  - Refactor: avoid global side-effect + cleanup [#62](https://github.com/logstash-plugins/logstash-input-syslog/pull/62)
    * avoid setting `BasicSocket.do_not_reverse_lookup` as it has side effects for others 

## 3.4.3
  - [DOC] Added expanded descriptions and requirements for facility_labels and severity_labels. [#52](https://github.com/logstash-plugins/logstash-input-syslog/pull/52)

## 3.4.2
  - Remove (deprecated) dependency on thread_safe gem.
  - CI: upgrade testing [#58](https://github.com/logstash-plugins/logstash-input-syslog/pull/58)
  - [DOC] Correct example for `timezone` option [#53](https://github.com/logstash-plugins/logstash-input-syslog/pull/53)

## 3.4.1
  - Docs: Set the default_codec doc attribute.

## 3.4.0
  - Allow the syslog field to be a configurable option.  This is useful for when codecs change
    the field containing the syslog data (e.g. the CEF codec).

## 3.3.0
  - Make the grok pattern a configurable option

## 3.2.4
  - Fix issue where stopping a pipeline (e.g., while reloading configuration) with active inbound syslog connections could cause Logstash to crash

## 3.2.3
  - Update gemspec summary

## 3.2.2
  - Fix some documentation issues

## 3.2.0
  - Add support for proxy protocol.

## 3.1.1
  - Move one log message from info to debug to avoid noise

## 3.1.0
  - Add metrics for events, messages received, errors and connections attemps happening during execution time.

## 3.0.2
  - Relax constraint on logstash-core-plugin-api to >= 1.60 <= 2.99

## 3.0.1
  - Republish all the gems under jruby.
## 3.0.0
  - Update the plugin to the version 2.0 of the plugin api, this change is required for Logstash 5.0 compatibility. See https://github.com/elastic/logstash/issues/5141
# 2.0.5
  - Temporary specs fix, see https://github.com/logstash-plugins/logstash-input-syslog/pull/25
# 2.0.4
  - Depend on logstash-core-plugin-api instead of logstash-core, removing the need to mass update plugins on major releases of logstash
# 2.0.3
  - New dependency requirements for logstash-core for the 5.0 release
## 2.0.0
 - Plugins were updated to follow the new shutdown semantic, this mainly allows Logstash to instruct input plugins to terminate gracefully,
   instead of using Thread.raise on the plugins' threads. Ref: https://github.com/elastic/logstash/pull/3895
 - Dependency on logstash-core update to 2.0

# 1.0.1
- fix deprecation warning from `concurrent-ruby`
