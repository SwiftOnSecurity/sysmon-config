# Sysmon Threat Intelligence Configuration #

This is a Microsoft Sysinternals Sysmon configuration file template with default high-quality event tracing.

The file provided should function as a great starting point for system monitoring in a self-contained package. This configuration and results should give you a good idea of what's possible for Sysmon.

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;**[sysmonconfig-export.xml](https://github.com/ion-storm/sysmon-config/blob/master/sysmonconfig-export.xml)**

Because virtually every line is commented and sections are marked with explanations, it should also function as a tutorial for Sysmon and a guide to critical monitoring areas in Windows systems. It demonstrates a lot of what I wish I knew when I began with Sysmon in 2014.

Pull requests and issue tickets are welcome, and new additions will be credited in-line or on Git.

Note: Exact syntax and filtering choices are deliberate to catch appropriate entries and to have as little performance impact as possible. Sysmon's filtering abilities are different than the built-in Windows auditing features, so often a different approach is taken than the normal static listing of every possible important area.

## Use ##

### Auto-Install ###
~~~~
Install Sysmon.bat
~~~~

### Install ###
Run with administrator rights
~~~~
sysmon.exe -accepteula -i sysmonconfig-export.xml
~~~~

### Update existing configuration ###
Run with administrator rights
~~~~
sysmon.exe -c sysmonconfig-export.xml
~~~~

### Uninstall ###
Run with administrator rights
~~~~
sysmon.exe -u
~~~~

## Hide Sysmon from services.msc ##
~~~~
Hide:
sc sdset Sysmon D:(D;;DCLCWPDTSD;;;IU)(D;;DCLCWPDTSD;;;SU)(D;;DCLCWPDTSD;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)S:(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)
Restore:
sc sdset Sysmon D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)S:(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)

~~~~

### Graylog Configuration ###


### Sysmon Pipeline Rules ###

## Stage -1 ##
# sysmon cleanup (gl2_source_fix) #
~~~~
// This rule is cleaning up the message
// -- It addresses an issue with older filebeat versions, which can have trouble with the 'source' field 
// -- The rule will not cause any trouble with filebeat versions that do not have that issue
rule "sysmon cleanup (gl2_source_fix)"
when
    is_not_null($message.winlogbeat_fields_gl2_source_collector)
then
    set_field("gl2_source_collector", to_string($message.winlogbeat_fields_gl2_source_collector));
    remove_field("winlogbeat_fields_gl2_source_collector");
end
~~~~

# sysmon cleanup #
~~~~
// Sysmon Installation
// -- Sysmon has to be installed on Windows, and be run with: sysmon –i –accepteula –h md5 –n -l 
// -- Transport should be a winlogbeat
// -- Consider using the Graylog Sidecar to manage winlogbeat remotely
rule "sysmon cleanup"
when
    // Only run for Sysmon messages
    has_field("winlogbeat_source_name") AND contains(to_string($message.winlogbeat_source_name), "Microsoft-Windows-Sysmon")
then

    // Rename some fields to clean up
    rename_field("winlogbeat_computer_name", "sysmon_computer_name");
    rename_field("winlogbeat_event_data_Image", "sysmon_data_process");
    rename_field("winlogbeat_event_data_UtcTime", "sysmon_data_utc_time");
    rename_field("winlogbeat_event_id", "sysmon_event_id");
    rename_field("winlogbeat_level", "sysmon_data_level");
    rename_field("winlogbeat_task", "sysmon_task");
    rename_field("winlogbeat_event_data_User", "sysmon_data_user");
    rename_field("winlogbeat_event_data_TargetFilename", "sysmon_data_file_created");
    rename_field("winlogbeat_event_data_CreationUtcTime", "sysmon_data_file_created_time");
    rename_field("winlogbeat_event_data_PreviousCreationUtcTime", "sysmon_data_file_created_time_previous");
    rename_field("winlogbeat_user_name", "sysmon_data_user_name");
    rename_field("winlogbeat_thread_id", "sysmon_thread_id"); 
    rename_field("winlogbeat_user_domain", "sysmon_user_domain");
    rename_field("winlogbeat_user_identifier", "sysmon_user_identifier");
    rename_field("winlogbeat_user_type", "sysmon_user_type");
    rename_field("winlogbeat_event_data_DestinationHostname", "sysmon_dns_lookup");
    rename_field("winlogbeat_event_data_DestinationIp", "sysmon_dns_lookup_ip");
    rename_field("winlogbeat_event_data_DestinationPort", "sysmon_dest_port");
    rename_field("winlogbeat_event_data_DestinationPortName", "sysmon_dest_port_name");
    rename_field("winlogbeat_event_data_Initiated", "sysmon_con_initiated");
    rename_field("winlogbeat_event_data_Protocol", "sysmon_con_proto");
    rename_field("winlogbeat_event_data_SourceHostname", "sysmon_src_name");
    rename_field("winlogbeat_event_data_SourceIp", "sysmon_src_ip");
    rename_field("winlogbeat_event_data_SourcePort", "sysmon_src_port");
    rename_field("winlogbeat_event_data_SourcePortName", "sysmon_src_port_name");
    rename_field("winlogbeat_event_data_CommandLine", "sysmon_cmd_event");
    rename_field("winlogbeat_event_data_CurrentDirectory", "sysmon_cmd_location");
    rename_field("winlogbeat_event_data_Hashes", "sysmon_cmd_hash");
    rename_field("winlogbeat_event_data_IntegrityLevel", "sysmon_cmd_integrity");
    rename_field("winlogbeat_event_data_LogonId", "sysmon_cmd_logon_id");
    rename_field("winlogbeat_event_data_ParentCommandLine", "sysmon_cmd_parent_cmd");
    rename_field("winlogbeat_event_data_ParentImage", "sysmon_cmd_parent_file");
    rename_field("winlogbeat_event_data_ParentProcessId", "sysmon_cmd_parent_pid");
    rename_field("winlogbeat_event_data_TerminalSessionId", "sysmon_cmd_terminal_pid");
    rename_field("winlogbeat_event_data_LogonGuid", "sysmon_cmd_logon_guid");
    rename_field("winlogbeat_event_data_ParentProcessGuid", "sysmon_cmd_parent_guid");
    rename_field("winlogbeat_event_data_TargetObject", "sysmon_registry_object");
    rename_field("winlogbeat_event_EventType", "sysmon_registry_Type");
    rename_field("winlogbeat_event_data_Details", "sysmon_registry_set");
    rename_field("winlogbeat_event_data_SourceImage", "sysmon_paccess_source_img");
    rename_field("winlogbeat_event_data_SourceProcessGUID", "sysmon_paccess_pguid");
    rename_field("winlogbeat_event_data_SourceProcessId", "sysmon_paccess_pid");
    rename_field("winlogbeat_event_data_SourceThreadId", "sysmon_paccess_threadid");
    rename_field("winlogbeat_event_data_TargetImage", "sysmon_paccess_target_image");
    rename_field("winlogbeat_event_data_TargetProcessGUID", "sysmon_paccess_target_guid");
    rename_field("winlogbeat_event_data_TargetProcessid", "sysmon_paccess_target_pid");
    rename_field("winlogbeat_event_data_DestinationIp_geolocation", "sysmon_dns_lookup_ip_geolocation");
    rename_field("winlogbeat_event_data_PipeName", "sysmon_pipe_name");
    rename_field("winlogbeat_event_data_ProcessId", "sysmon_pipe_pid");
    rename_field("winlogbeat_process_id", "sysmon_img_pid");
    rename_field("winlogbeat_event_data_ImageLoaded", "sysmon_imgloaded");
    rename_field("winlogbeat_event_data_SignatureStatus", "sysmon_signatureStatus");
    rename_field("winlogbeat_event_data_Signed", "sysmon_signed");

    // Remove clutter.
    let fix = regex("^\\{(\\S+)\\}$", to_string($message.winlogbeat_event_data_ProcessGuid));
    set_field("sysmon_data_process_guid", to_string(fix["0"]));
    remove_field("winlogbeat_event_data_ProcessGuid");

    let fix = regex("^\\{(\\S+)\\}$", to_string($message.winlogbeat_provider_guid));
    set_field("sysmon_data_provider_gui", to_string(fix["0"]));
    remove_field("winlogbeat_provider_guid");


    // Remove unwanted fields
    remove_field("name");
    remove_field("tags");
    remove_field("type");

    // Remove winlogbeats fields we don't need
    //remove_field("winlogbeat_event_data_ProcessId");
    //remove_field("winlogbeat_log_name");
    //remove_field("winlogbeat_opcode");
    //remove_field("winlogbeat_process_id");
    //remove_field("winlogbeat_record_number");
    //remove_field("winlogbeat_source_name");
    //remove_field("winlogbeat_tags");
    //remove_field("winlogbeat_type");
    //remove_field("winlogbeat_version");
    //remove_field("winlogbeat_event_data_SourceIsIpv6");
    //remove_field("winlogbeat_event_data_DestinationIsIpv6");
end
~~~~

# Stage 0 #
~~~~
// Threat Intelligence enrichment
// --- Needs installed Graylog Threat Intel plugin : https://github.com/Graylog2/graylog-plugin-threatintel
rule "sysmon threatintel"
when
   // To save CPU cycles, only run if there is something to look up
   has_field("sysmon_dns_lookup") OR has_field("sysmon_dns_lookup_ip") OR has_field("sysmon_src_ip")
then

    // look up the requested DNS captured by sysmon
    // this will be the most fired rule
    let sysmon_dns_lookup_intel = threat_intel_lookup_domain(to_string($message.sysmon_dns_lookup), "sysmon_dns_lookup");
    set_fields(sysmon_dns_lookup_intel);

    // look up the ip from the DNS answer
    // if we do not monitor the dns, then this might be nice to have
    let sysmon_lookup_ip_answer_intel = threat_intel_lookup_ip(to_string($message.sysmon_dns_lookup_ip), "sysmon_dns_lookup_ip");
    set_fields(sysmon_lookup_ip_answer_intel);

    // look up the requesting IP 
    // this is useful if dealing with non internal IPs 
    // so you know if your IP is seen as a problem
    let sysmon_src_ip_answer_intel = threat_intel_lookup_ip(to_string($message.sysmon_src_ip), "sysmon_src_ip");
    set_fields(sysmon_src_ip_answer_intel);

    // WHOIS lookup. This is disabled by default. Enable and carefully watch latency and performance.
    let sysmon_dns_lookup_ip_whois = whois_lookup_ip(to_string($message.sysmon_dns_lookup_ip), "sysmon_dns_lookup_ip");
    set_fields(sysmon_dns_lookup_ip_whois);
    
    //AlienVault OTX
    let intel = otx_lookup_ip(to_string($message.sysmon_src_ip));
    let intel = otx_lookup_domain(to_string($message.sysmon_dns_lookup_ip));
    set_field("otx_threat_indicated", intel.otx_threat_indicated);
    set_field("otx_threat_ids", intel.otx_threat_ids);
    set_field("otx_threat_names", intel.otx_threat_names);

end
~~~~

# Stage 1 #
~~~~
rule "sysmon threatintel inflate"
when
    // run only if one of the fields is true
    to_bool($message.sysmon_dns_lookup_ip_threat_indicated) OR to_bool($message.sysmon_dns_lookup_threat_indicated) OR to_bool($message.sysmon_src_ip_threat_indicated) OR to_bool($message.otx_threat_indicated)
then

    // This is to make Graylog searches easy
    // -- Enables searches like threat_indicated:true
    set_field("threat_indicated", true);
end
~~~~
