# SophosXG_Graylog
Sophos XG Firewall - content pack, extraction rules, pipeline rules, streams, and a dashboard
 - Be sure to edit each widget query
 - Content pack contains everything
 - Content pack will be broken down
 - Contraints: Graylog-Server v3.3+

Graylog Extractor Rules
 - XG Content Filter Log Type 
```YAML
rule "XG Content Filter Type"
when
    to_string($message.log_type) == "Content Filtering"
then
    set_fields(
        grok(
            pattern: "status=%{QUOTEDSTRING:action}%{SPACE}priority=%{GREEDYDATA:priority}%{SPACE}fw_rule_id=%{INT:fw_rule_id}%{SPACE}user_name=%{QUOTEDSTRING:user_name}%{SPACE}user_gp=%{QUOTEDSTRING:user_group}%{SPACE}iap=%{INT:iap}%{SPACE}category=%{QUOTEDSTRING:category}%{SPACE}category_type=%{QUOTEDSTRING:category_type}%{SPACE}url=%{QUOTEDSTRING:url}%{SPACE}contenttype=%{QUOTEDSTRING:content_type}%{SPACE}override_token=%{QUOTEDSTRING:override_token}%{SPACE}httpresponsecode=%{QUOTEDSTRING:http_response_code}%{SPACE}src_ip=%{IP:src_ip}%{SPACE}dst_ip=%{IP:dst_ip}%{SPACE}protocol=%{QUOTEDSTRING:protocol}%{SPACE}src_port=%{INT:src_port}%{SPACE}dst_port=%{INT:dst_port}%{SPACE}sent_bytes=%{INT:sent_bytes;int}%{SPACE}recv_bytes=%{INT:recv_bytes;int}%{SPACE}domain=%{URIHOST:domain}%{SPACE}exceptions=%{DATA:exceptions}%{SPACE}activityname=%{QUOTEDSTRING:activity_name}%{SPACE}reason=%{QUOTEDSTRING:reason}%{SPACE}user_agent=%{QUOTEDSTRING:user_agent}%{SPACE}status_code=%{QUOTEDSTRING:status_code}%{SPACE}transactionid=%{DATA:transaction_id}%{SPACE}referer=%{QUOTEDSTRING:referer}%{SPACE}download_file_name=%{QUOTEDSTRING:downloaded_file_name}%{SPACE}download_file_type=%{QUOTEDSTRING:downloaded_file_type}%{SPACE}upload_file_name=%{QUOTEDSTRING}%{SPACE}upload_file_type=%{QUOTEDSTRING}%{SPACE}con_id=%{INT:con_id}%{SPACE}application=%{QUOTEDSTRING:application}%{SPACE}app_is_cloud=%{INT:app_is_cloud;boolean}",
            value: to_string($message.message),
            only_named_captures: true
        )
    );
end
```
 - XG Firewall Log Type
 ```YAML
 rule "XG Firewall Type"
when
    to_string($message.log_type) == "Firewall"
then
    set_fields(
        grok(
            pattern: "status=%{QUOTEDSTRING:action}%{SPACE}priority=%{WORD:priority}%{SPACE}duration=%{INT:duration}%{SPACE}fw_rule_id=%{INT:fw_rule_id}%{SPACE}policy_type=%{INT:policy_type}%{SPACE}user_name=%{QUOTEDSTRING:user_name}%{SPACE}user_gp=%{QUOTEDSTRING:user_group}%{SPACE}iap=%{INT:iap}%{SPACE}ips_policy_id=%{INT:ips_policy_id}%{SPACE}appfilter_policy_id=%{INT:app_filter_policy_id}%{SPACE}application=%{QUOTEDSTRING:application}%{SPACE}application_risk=%{INT:application_risk}%{SPACE}application_technology=%{QUOTEDSTRING:application_technology}%{SPACE}application_category=%{QUOTEDSTRING:application_category}%{SPACE}in_interface=%{QUOTEDSTRING:in_interface}%{SPACE}out_interface=%{QUOTEDSTRING:out_interface}%{SPACE}src_mac=%{DATA:src_mac}%{SPACE}src_ip=%{DATA:src_ip}%{SPACE}src_country_code=%{DATA:src_country_code}%{SPACE}dst_ip=%{DATA:dst_ip}%{SPACE}dst_country_code=%{DATA:dst_country_code}%{SPACE}protocol=%{QUOTEDSTRING:protocol}%{SPACE}(src_port=%{INT:src_port}%{SPACE}dst_port=%{INT:dst_port})?(icmp_type=%{INT:icmp_type}%{SPACE}icmp_code=%{INT:icmp_code})?%{SPACE}sent_pkts=%{INT:sent_pkts;int}%{SPACE}recv_pkts=%{INT:recv_pkts;int}%{SPACE}sent_bytes=%{INT:sent_bytes;int}%{SPACE}recv_bytes=%{INT:recv_bytes;int}%{SPACE}tran_src_ip=%{DATA:tran_src_ip}%{SPACE}tran_src_port=%{INT:tran_src_port}%{SPACE}tran_dst_ip=%{DATA:tran_dst_ip}%{SPACE}tran_dst_port=%{INT:tran_dst_port}%{SPACE}srczonetype=%{QUOTEDSTRING:src_zone_type}%{SPACE}srczone=%{QUOTEDSTRING:src_zone}%{SPACE}dstzonetype=%{QUOTEDSTRING:dst_zone_type}%{SPACE}dstzone=%{QUOTEDSTRING:dst_zone}%{SPACE}dir_disp=%{QUOTEDSTRING:dir_disp}%{SPACE}(connevent=%{QUOTEDSTRING:conn_event})?%{SPACE}connid=%{QUOTEDSTRING:conn_id}%{SPACE}vconnid=%{QUOTEDSTRING:v_conn_id}%{SPACE}hb_health=%{QUOTEDSTRING:hb_health}%{SPACE}message=%{QUOTEDSTRING:fw_message}%{SPACE}appresolvedby=%{QUOTEDSTRING:app_resolved_by}%{SPACE}app_is_cloud=%{INT:app_is_cloud;boolean}",
            value: to_string($message.message),
            only_named_captures: true
        )
    );
end
 ```
