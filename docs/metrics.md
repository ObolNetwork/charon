# Prometheus Metrics

This document contains all the prometheus metrics exposed by a charon node.

All metrics contain the following labels, so they are omitted from the table below:
- `cluster_hash`: The cluster lock hash uniquely identifying the cluster.
- `clustter_name`: The cluster lock name.
- `cluster_network`: The cluster network name; goerli, mainnet, etc.
- `cluster_peer`: The name of this node in the cluster. It is determined from the operator ENR.

The `cluster_*` labels uniquely identify a specific node`s metrics which is required
when storing metrics from multiple nodes or clusters in one Prometheus instance.

| Name | Type | Help | Labels |
|---|---|---|---|
| `app_beacon_node_peers` | Gauge | Gauge set to the peer count of the upstream beacon node |  |
| `app_beacon_node_version` | Gauge | Constant gauge with label set to the node version of the upstream beacon node | `version` |
| `app_eth2_errors_total` | Counter | Total number of errors returned by eth2 beacon node requests | `endpoint` |
| `app_eth2_latency_seconds` | Histogram | Latency in seconds for eth2 beacon node requests | `endpoint` |
| `app_git_commit` | Gauge | Constant gauge with label set to current git commit hash | `git_hash` |
| `app_health_checks` | Gauge | Application health checks by name and severity. Set to 1 for failing, 0 for ok. | `severity, name` |
| `app_log_error_total` | Counter | Total count of logged errors by topic | `topic` |
| `app_log_warn_total` | Counter | Total count of logged warnings by topic | `topic` |
| `app_monitoring_readyz` | Gauge | Set to 1 if the node is operational and monitoring api `/readyz` endpoint is returning 200s. Else `/readyz` is returning 500s and this metric is either set to 2 if the beacon node is down, or3 if the beacon node is syncing, or4 if quorum peers are not connected. |  |
| `app_peer_name` | Gauge | Constant gauge with label set to the name of the cluster peer | `peer_name` |
| `app_peerinfo_clock_offset_seconds` | Gauge | Peer clock offset in seconds | `peer` |
| `app_peerinfo_git_commit` | Gauge | Constant gauge with git_hash label set to peer`s git commit hash. | `peer, git_hash` |
| `app_peerinfo_index` | Gauge | Constant gauge set to the peer index in the cluster definition | `peer` |
| `app_peerinfo_mev_enabled` | Gauge | Set to 1 if mev is enabled on this peer, else 0 if disabled. | `peer` |
| `app_peerinfo_start_time_secs` | Gauge | Constant gauge set to the peer start time of the binary in unix seconds | `peer` |
| `app_peerinfo_version` | Gauge | Constant gauge with version label set to peer`s charon version. | `peer, version` |
| `app_peerinfo_version_support` | Gauge | Set to 1 if the peer`s version is supported by (compatible with) the current version, else 0 if unsupported. | `peer` |
| `app_start_time_secs` | Gauge | Gauge set to the app start time of the binary in unix seconds |  |
| `app_version` | Gauge | Constant gauge with label set to current app version | `version` |
| `cluster_network` | Gauge | Constant gauge with label set to the current network (chain) | `network` |
| `cluster_operators` | Gauge | Number of operators in the cluster lock |  |
| `cluster_threshold` | Gauge | Aggregation threshold in the cluster lock |  |
| `cluster_validators` | Gauge | Number of validators in the cluster lock |  |
| `core_bcast_broadcast_delay_seconds` | Histogram | Duty broadcast delay from start of slot in seconds by type | `duty` |
| `core_bcast_broadcast_total` | Counter | The total count of successfully broadcast duties by type | `duty` |
| `core_bcast_recast_errors_total` | Counter | The total count of failed recasted registrations by source; `pregen` vs `downstream` | `source` |
| `core_bcast_recast_registration_total` | Counter | The total number of unique validator registration stored in recaster per pubkey | `pubkey` |
| `core_bcast_recast_total` | Counter | The total count of recasted registrations by source; `pregen` vs `downstream` | `source` |
| `core_consensus_decided_rounds` | Gauge | Number of rounds it took to decide consensus instances by duty and timer type. | `duty, timer` |
| `core_consensus_duration_seconds` | Histogram | Duration of a consensus instance in seconds by duty and timer type. | `duty, timer` |
| `core_consensus_error_total` | Counter | Total count of consensus errors |  |
| `core_consensus_timeout_total` | Counter | Total count of consensus timeouts by duty and timer type. | `duty, timer` |
| `core_parsigdb_exit_total` | Counter | Total number of partially signed voluntary exits per public key | `pubkey` |
| `core_scheduler_current_epoch` | Gauge | The current epoch |  |
| `core_scheduler_current_slot` | Gauge | The current slot |  |
| `core_scheduler_duty_total` | Counter | The total count of duties scheduled by type | `duty` |
| `core_scheduler_skipped_slots_total` | Counter | Total number times slots were skipped |  |
| `core_scheduler_validator_balance_gwei` | Gauge | Total balance of a validator by public key | `pubkey_full, pubkey` |
| `core_scheduler_validator_status` | Gauge | Gauge with validator pubkey and status as labels, value=1 is current status, value=0 is previous. | `pubkey_full, pubkey, status` |
| `core_scheduler_validators_active` | Gauge | Number of active validators |  |
| `core_tracker_expect_duties_total` | Counter | Total number of expected duties (failed + success) by type | `duty` |
| `core_tracker_failed_duties_total` | Counter | Total number of failed duties by type | `duty` |
| `core_tracker_failed_duty_reasons_total` | Counter | Total number of failed duties by type and reason code | `duty, reason` |
| `core_tracker_inclusion_delay` | Gauge | Cluster`s average attestation inclusion delay in slots |  |
| `core_tracker_inclusion_missed_total` | Counter | Total number of broadcast duties never included in any block by type | `duty` |
| `core_tracker_inconsistent_parsigs_total` | Counter | Total number of duties that contained inconsistent partial signed data by duty type | `duty` |
| `core_tracker_participation` | Gauge | Set to 1 if peer participated successfully for the given duty or else 0 | `duty, peer` |
| `core_tracker_participation_expected_total` | Counter | Total number of expected participations (fail + success) by peer and duty type | `duty, peer` |
| `core_tracker_participation_missed_total` | Counter | Total number of missed participations by peer and duty type | `duty, peer` |
| `core_tracker_participation_success_total` | Counter | Total number of successful participations by peer and duty type | `duty, peer` |
| `core_tracker_participation_total` | Counter | Total number of successful participations by peer and duty type | `duty, peer` |
| `core_tracker_success_duties_total` | Counter | Total number of successful duties by type | `duty` |
| `core_tracker_unexpected_events_total` | Counter | Total number of unexpected events by peer | `peer` |
| `core_validatorapi_request_error_total` | Counter | The total number of validatorapi request errors | `endpoint, status_code` |
| `core_validatorapi_request_latency_seconds` | Histogram | The validatorapi request latencies in seconds by endpoint | `endpoint` |
| `p2p_peer_connection_total` | Counter | Total number of libp2p connections per peer. | `peer` |
| `p2p_peer_connection_types` | Gauge | Current number of libp2p connections by peer and type (`direct` or `relay`). Note that peers may have multiple connections. | `peer, type` |
| `p2p_peer_network_receive_bytes_total` | Counter | Total number of network bytes received from the peer by protocol. | `peer, protocol` |
| `p2p_peer_network_sent_bytes_total` | Counter | Total number of network bytes sent to the peer by protocol. | `peer, protocol` |
| `p2p_peer_streams` | Gauge | Current number of libp2p streams by peer, direction (`inbound` or `outbound` or `unknown`) and protocol. | `peer, direction, protocol` |
| `p2p_ping_error_total` | Counter | Total number of ping errors per peer | `peer` |
| `p2p_ping_latency_secs` | Histogram | Ping latencies in seconds per peer | `peer` |
| `p2p_ping_success` | Gauge | Whether the last ping was successful (1) or not (0). Can be used as proxy for connected peers | `peer` |
| `p2p_reachability_status` | Gauge | Current libp2p reachability status of this node as detected by autonat: unknown(0), public(1) or private(2). |  |
| `p2p_relay_connections` | Gauge | Connected relays by name | `peer` |
| `relay_p2p_active_connections` | Gauge | Current number of active connections by peer and cluster | `peer, peer_cluster` |
| `relay_p2p_connection_total` | Counter | Total number of new connections by peer and cluster | `peer, peer_cluster` |
| `relay_p2p_network_receive_bytes_total` | Counter | Total number of network bytes received from the peer and cluster | `peer, peer_cluster` |
| `relay_p2p_network_sent_bytes_total` | Counter | Total number of network bytes sent to the peer and cluster | `peer, peer_cluster` |
| `relay_p2p_ping_latency` | Histogram | Ping latency by peer and cluster | `peer, peer_cluster` |
