# frozen_string_literal: true

# copyright: 2015, The Authors
# license: All rights reserved

title 'Osquery Windows section'

osquery_confdir = attribute('osquery_dir', default: 'C:\Program Files\osquery', description: 'osquery program directory')
osquery_vardir = attribute('osquery_dir', default: 'C:\ProgramData\osquery', description: 'osquery.db directory')
osquery_std_logs = attribute('osquery_std_logs', default: true, description: 'Check osquery use default file logging')
osquery_logdir = attribute('osquery_logdir', default: 'C:\Program Files\osquery\log', description: 'osquery log directory')

control 'osquerywin-1.0' do # A unique ID for this control
  impact 0.7 # The criticality, if this control fails.
  title 'Osquery should be present'
  desc 'Ensure Osqueryi and osqueryd executables and configuration are present'
  only_if { os.family == 'windows' }
  describe file(osquery_confdir) do
    it { should be_directory }
  end
  describe file("#{osquery_vardir}/osquery.db") do
    it { should be_directory }
  end
  describe file("#{osquery_confdir}/osquery.conf") do
    it { should be_file }
  end
  describe file("#{osquery_confdir}/osqueryi.exe") do
    it { should be_file }
    it { should be_executable }
  end
  describe command("#{osquery_confdir}/osqueryi.exe --config_path #{osquery_confdir}/osquery.conf --config_check --verbose") do
    its('stdout') { should_not match 'Error' }
    its('stderr') { should_not match 'Error' }
  end
end

control 'osquerywin-2.0' do
  impact 0.7
  title 'Osqueryd should be running'
  desc 'Ensure osqueryd is running'
  only_if { os.family == 'windows' }
  describe processes('osqueryd') do
    its('list.length') { should eq 2 }
  end
end

if osquery_std_logs
  control 'osquerywin-3.0' do
    impact 0.7
    title 'Osqueryd should have log files'
    desc 'Ensure osqueryd file logs file are present'
    only_if { os.family == 'windows' }
    describe file("#{osquery_logdir}/osqueryd.results.log") do
      it { should be_file }
      # its('content') { should match '{"name":"pack_osquery-custom-pack_process_binding_to_ports","hostIdentifier":' }
      # its('content') { should match 'hostIdentifier' }
    end
    describe file("#{osquery_logdir}/osqueryd.INFO") do
      it { should be_file }
      its('content') { should match 'Log file created at:' }
      its('content') { should match 'Running on machine: ' }
      its('content') { should match 'Log line format: ' }
    end
  end

  control 'osquerywin-4.0' do
    impact 0.7
    title 'Osqueryd updated log files'
    only_if { os.family == 'windows' }
    desc 'Ensure osqueryd logs file were updated less than 900s in the past'
    describe file("#{osquery_logdir}/osqueryd.results.log").mtime.to_i do
      it { should <= Time.now.to_i }
      it { should >= Time.now.to_i - 900 }
    end
    describe file("#{osquery_logdir}/osqueryd.INFO").mtime.to_i do
      it { should <= Time.now.to_i }
      it { should >= Time.now.to_i - 900 }
    end
  end
end
