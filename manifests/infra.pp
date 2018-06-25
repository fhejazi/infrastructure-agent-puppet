# == Class: newrelic::infra
#
# === Required Parameters
# [*ensure*]
#   Infrastructure agent version ('absent' will uninstall)
#
# [*service_ensure*]
#   Infrastructure agent service status (default 'running')
#
# [*license_key*]
#   New Relic license key
#
# [*package_repo_ensure*]
#   Optional flag to disable setting up New Relic's package repo.
#   This is useful in the event the newrelic-infra package has been
#   mirrored to a repo that already exists on the system
#
# [*proxy*]
#   Optional value for directing the agent to use a proxy in http(s)://domain.or.ip:port format
#
# [*display_name*]
#   Optional. Override the auto-generated hostname for reporting.
#
# [*verbose*]
#   Optional. Enables verbose logging for the agent when set the value with 1, the default value is 0.
#
# [*log_file*]
#   Optional. To log to another location, provide a full path and file name. When not set, the agent logs to the system log files.
#   Typical default locations:
#   - Amazon Linux, CentOS, RHEL: `/var/log/messages`
#   - Debian, Ubuntu: `/var/log/syslog`
#   - Windows Server: `C:\Program Files\New Relic\newrelic-infra\newrelic-infra.log`
#
# [*custom_attributes*]
#   Optional hash of attributes to assign to this host (see docs https://docs.newrelic.com/docs/infrastructure/new-relic-infrastructure/configuration/configure-infrastructure-agent#attributes)
#
# [*custom_configs*]
#   Optional. A hash of agent configuration directives that are not exposed explicitly. Example:
#   {'payload_compression' => 0, 'selinux_enable_semodule' => false}
# === Authors
#
# @fhejazi
#
class newrelic::infra (
  $ensure               = 'latest',
  $service_ensure       = 'running',
  $license_key          = '',
  $package_repo_ensure  = 'present',
  $proxy                = '',
  $display_name         = '',
  $verbose              = '',
  $log_file             = '',
  $custom_attributes    = {},
  $custom_configs       = {},
) {
  # Validate license key
  if $license_key == '' {
    fail('New Relic license key not provided')
  }

  # Setup agent package repo
  case $::operatingsystem {
    'Debian', 'Ubuntu': {
      ensure_packages('apt-transport-https')
      apt::source { 'newrelic_infra-agent':
        ensure       => $package_repo_ensure,
        location     => 'https://download.newrelic.com/infrastructure_agent/linux/apt',
        release      => $::lsbdistcodename,
        repos        => 'main',
        architecture => 'amd64',
        key          => {
            'id'     => 'A758B3FBCD43BE8D123A3476BB29EE038ECCE87C',
            'source' => 'https://download.newrelic.com/infrastructure_agent/gpg/newrelic-infra.gpg',
        },
        require      => Package['apt-transport-https'],
        notify       => Exec['apt_update'],
      }
      exec { 'newrelic_infra_apt_get_update':
        command     => 'apt-get update',
        cwd         => '/tmp',
        path        => ['/usr/bin'],
        require     => Apt::Source['newrelic_infra-agent'],
        subscribe   => Apt::Source['newrelic_infra-agent'],
        refreshonly => true,
      }
      package { 'newrelic-infra':
        ensure  => $ensure,
        require => Exec['newrelic_infra_apt_get_update'],
      }
    }
    'RedHat', 'CentOS', 'Amazon', 'OracleLinux': {
      if ($::operatingsystem == 'Amazon') {
        $repo_releasever = '6'
      } else {
        $repo_releasever = $::operatingsystemmajrelease
      }
      yumrepo { 'newrelic_infra-agent':
        ensure        => $package_repo_ensure,
        descr         => 'New Relic Infrastructure',
        baseurl       => "https://download.newrelic.com/infrastructure_agent/linux/yum/el/${repo_releasever}/x86_64",
        gpgkey        => 'https://download.newrelic.com/infrastructure_agent/gpg/newrelic-infra.gpg',
        gpgcheck      => true,
        repo_gpgcheck => true,
      }
      package { 'newrelic-infra':
        ensure  => $ensure,
        require => Yumrepo['newrelic_infra-agent'],
      }
    }
    'OpenSuSE', 'SuSE', 'SLED', 'SLES': {
      exec { 'add_newrelic_repo':
        creates => '/etc/zypp/repos.d/newrelic-infra.repo',
        command => "/usr/bin/zypper addrepo --no-gpgcheck --repo http://download.newrelic.com/infrastructure_agent/beta/linux/zypp/sles/${::operatingsystemrelease}/x86_64/newrelic-infra.repo",
        path    => ['/usr/local/sbin', '/usr/local/bin', '/sbin', '/bin', '/usr/bin'],
        notify  => Exec['install_newrelic_agent']
      }
      exec { 'install_newrelic_agent':
        command     => '/usr/bin/zypper install -y newrelic-infra',
        path        => ['/usr/local/sbin', '/usr/local/bin', '/sbin', '/bin', '/usr/bin'],
        require     => Exec['add_newrelic_repo'],
        refreshonly => true,
      }
    }

    'Windows': {
      # Windows Section
        $installer_url = 'https://download.newrelic.com/infrastructure_agent/windows/newrelic-infra.msi'
        $target_file = 'c:\windows\temp\newrelic-infra.msi'

      # Download infra-agent:
      exec { 'download_infra_agent':
        command  => "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; Invoke-WebRequest ${installer_url} -OutFile ${target_file}",
        creates  => $target_file,
        provider => powershell,
      }

      # Install infra-agent:
      package { 'newrelic-agent':
        ensure => installed,
        provider => 'windows',
        source => $target_file,
        install_options => [ '/qn' ],
        require => Exec['download_infra_agent'],
      }~>

      # Setup the infra agent config file
      file { 'newrelic-infra.yml':
        path    => 'c:\Program Files\New Relic\newrelic-infra\newrelic-infra.yml',
        ensure  => file,
        content => template('newrelic_infra/newrelic-infra.yml.erb'),
      }~>

      # Start the agent:
      service { 'newrelic-infra':
        ensure => 'running'
      }
    }

    default: {
      fail('New Relic Infrastructure agent is not yet supported on this platform')
    }
  }

  # Do this only if os::family != Windows
  # Setup agent config
  if ($::operatingsystem != 'Windows') {
    file { '/etc/newrelic-infra.yml':
      ensure  => 'present',
      owner   => 'root',
      group   => 'root',
      mode    => '0640',
      content => template('newrelic_infra/newrelic-infra.yml.erb'),
      notify  => Service['newrelic-infra'] # Restarts the agent service on config changes
    }
  }

  # we use Upstart on CentOS 6 systems and derivatives, which is not the default
  if (($::operatingsystem == 'CentOS' or $::operatingsystem == 'RedHat')and $::operatingsystemmajrelease == '6')
  or ($::operatingsystem == 'Amazon') {
    service { 'newrelic-infra':
      ensure  => $service_ensure,
      start   => '/sbin/start newrelic-infra',
      stop    => '/sbin/stop newrelic-infra',
      status  => '/sbin/status newrelic-infra',
      require => Package['newrelic-infra'],
    }
  } elsif $::operatingsystem == 'SLES' {
    # Setup agent service for sysv-init service manager
    service { 'newrelic-infra':
      ensure  => $service_ensure,
      start   => '/etc/init.d/newrelic-infra start',
      stop    => '/etc/init.d/newrelic-infra stop',
      status  => '/etc/init.d/newrelic-infra status',
      require => Exec['install_newrelic_agent']
    }
  } else {
    unless ($::operatingsystem == 'Windows') {
      # Setup agent service
      service { 'newrelic-infra':
        ensure  => $service_ensure,
        require => Package['newrelic-infra'],
      }
    }
  }
}
