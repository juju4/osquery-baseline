# encoding: utf-8
# copyright: 2015, The Authors
# license: All rights reserved

title 'Osquery section'

if os.darwin?
  osquery_confdir = '/var/osquery'
  osquery_vardir = '/var/osquery'
  osquery_usrdir = '/usr/local/bin'
else
  osquery_confdir = '/etc/osquery'
  osquery_vardir = '/var/osquery'
  osquery_usrdir = '/usr/bin'
end


control 'osquery-1.0' do                        # A unique ID for this control
  impact 0.7                                # The criticality, if this control fails.
  title 'Osquery should be present'
  desc 'Ensure Osqueryi and osqueryd executables and configuration are present'
  describe file(osquery_confdir) do
    it { should be_directory }
  end
  describe file("#{osquery_vardir}/osquery.db") do
    it { should be_directory }
    it { should be_owned_by 'root' }
    its('mode') { should cmp '0700' }
  end
  describe file("#{osquery_confdir}/osquery.conf") do
    it { should be_file }
  end
  describe file("#{osquery_usrdir}/osqueryi") do
    it { should be_file }
    it { should be_executable }
    it { should be_owned_by 'root' }
  end
  describe file("#{osquery_usrdir}/osqueryd") do
    it { should be_file }
    it { should be_executable }
    it { should be_owned_by 'root' }
  end
  describe command("osqueryi --config_path #{osquery_confdir}/osquery.conf --config_check --verbose") do
    its('stdout') { should_not match 'Error' }
    its('stderr') { should_not match 'Error' }
  end
end

control 'osquery-2.0' do
  impact 0.7
  title 'Osqueryd should be running'
  desc 'Ensure osqueryd is running'
  describe processes('osqueryd') do
    its('users') { should eq ['root'] }
    its('list.length') { should eq 1 }
  end
end

control 'osquery-3.0' do
  impact 0.7
  title 'Osqueryd should have log files'
  desc 'Ensure osqueryd logs file are present'
  describe file('/var/log/osquery/osqueryd.results.log') do
    it { should be_file }
    it { should be_owned_by 'root' }
    its('mode') { should cmp '0640' }
#    its('content') { should match '{"name":"pack_osquery-custom-pack_process_binding_to_ports","hostIdentifier":' }
#    its('content') { should match 'hostIdentifier' }
  end
  describe file('/var/log/osquery/osqueryd.INFO') do
    it { should be_file }
    it { should be_owned_by 'root' }
    its('mode') { should cmp '0644' }
    its('content') { should match 'Log file created at:' }
    its('content') { should match 'Running on machine: ' }
    its('content') { should match 'Log line format: ' }
  end
end

control 'osquery-4.0' do
  impact 0.7
  title 'Osqueryd updated log files'
  desc 'Ensure osqueryd logs file were updated less than 900s in the past'
  describe file('/var/log/osquery/osqueryd.results.log').mtime.to_i do
    it { should <= Time.now.to_i }
    it { should >= Time.now.to_i - 900}
  end
  describe file('/var/log/osquery/osqueryd.INFO').mtime.to_i do
    it { should <= Time.now.to_i }
    it { should >= Time.now.to_i - 900}
  end
end

