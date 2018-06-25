# == Class: newrelic::dotnet
#
# === Required Parameters
# [*ensure*]
#   .Net agent version ('absent' will uninstall)
#
# [*service_ensure*]
#   .Net agent service status (default 'running')
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
class newrelic::dotnet (
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

  # Setup .Net agent package repo
  case $::operatingsystem {

        $installer_url = 'https://download.newrelic.com/dot_net_agent/latest_release/newrelic-agent-win-x64-8.2.216.0.msi'
        $target_file = 'c:\windows\temp\newrelic-dotnet.msi'

      # Download .Net agent:
      exec { 'download_dotnet_agent':
        command  => "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; Invoke-WebRequest ${installer_url} -OutFile ${target_file}",
        creates  => $target_file,
        provider => powershell,
      }

      # Install .Net agent:
      package { 'newrelic-dotnet-agent':
        ensure => installed,
        provider => 'windows',
        source => $target_file,
        install_options => [ '/qn' ],
        require => Exec['download_dotnet_agent'],
      }~>

      # Setup the .Net agent config file
      file { 'newrelic-infra.yml':
        path    => 'c:\Program Files\New Relic\.NET Agent\newrelic.config',
        ensure  => file,
        content => template('newrelic_infra/newrelic.config.erb'),
      }~>

      # Start the .Net agent:
      service { 'newrelic-dotnet-agent':
        ensure => 'running'
      }
    }

    default: {
      fail('New Relic .Net agent is not yet supported on this platform')
    }
  }

    }
  }
}
