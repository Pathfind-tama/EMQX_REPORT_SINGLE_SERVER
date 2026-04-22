# CVE Report: EMQX MQTT QoS 2 Message Duplication in Single Server Mode

## Vulnerability Summary

**Title**: EMQX MQTT Broker QoS 2 Message Duplication Due to Non-Atomic Publish Operation

**Severity**: Medium

**CVSSv3 Score**: 5.9 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N)

**Affected Component**: EMQX Broker (Session Management)

**Vulnerability Type**: CWE-362 (Concurrent Execution using Shared Resource with Improper Synchronization)

**Affected Versions**: 
- EMQX 4.x (verified on 4.4.19)
- EMQX 5.x 
- EMQX 6.x (verified on 6.1.0-sf)

## Vulnerability Description

EMQX broker violates the MQTT QoS 2 "exactly once" delivery guarantee due to a non-atomic operation sequence when processing PUBLISH packets. The broker publishes messages to subscribers **before** recording the PacketId in the `awaiting_rel` structure, creating a critical time window where a crash can cause message duplication.

### Code Evidence

**Memory Session Implementation** (`apps/emqx/src/emqx_session_mem.erl`, lines 380-382):

```erlang
false ->
    Results = emqx_broker:publish(Msg),           % Line 380: Publish first
    AwaitingRel1 = maps:put(PacketId, Ts, AwaitingRel),  % Line 381: Record later
    {ok, Results, Session#session{awaiting_rel = AwaitingRel1}};
```

**Persistent Session Implementation** (`apps/emqx/src/emqx_persistent_session_ds.erl`, lines 520-522):

```erlang
undefined ->
    Results = emqx_broker:publish(Msg),           % Line 520: Publish first
    S = emqx_persistent_session_ds_state:put_awaiting_rel(PacketId, TS, S0),
    {ok, Results, ensure_state_commit_timer(Session#{s := S})};  % Line 522: Async commit
```

**Note**: The persistent session uses `ensure_state_commit_timer`, which commits state **asynchronously** via a timer, not synchronously.

## Trigger Conditions (Minimal Reproduction Steps)

### Prerequisites
1. EMQX broker running (any version 4.x/5.x/6.x)
2. MQTT client with QoS 2 support
3. At least one subscriber to the target topic

### Trigger Scenario

**Timing Window**: Between line 380 (or 520) and line 381 (or 522)

**Trigger Conditions**:
1. Client sends `PUBLISH` packet with QoS=2, PacketId=X to broker
2. Broker executes `emqx_broker:publish(Msg)` (line 380/520) - **message delivered to subscribers**
3. **[CRITICAL WINDOW]** Before executing `maps:put(PacketId, ...)` (line 381) or before async commit completes (line 522):
   - Broker process crashes (e.g., `kill -9`, OOM, segfault)
   - OR in persistent session: broker crashes before state commit timer fires
4. Broker restarts with empty `awaiting_rel` map
5. Client, not having received PUBREC, retransmits `PUBLISH` with DUP=1, same PacketId=X
6. Broker checks `awaiting_rel`, finds no record of PacketId=X
7. Broker executes `emqx_broker:publish(Msg)` again - **message duplicated**

### Why This is Hard to Reproduce

1. **Narrow Time Window**: The window between lines 380-381 is typically < 1ms
2. **Requires Precise Timing**: Crash must occur in this exact window
3. **Async Commit**: For persistent sessions, the commit timer delay varies
4. **No Direct Control**: External attackers cannot directly trigger broker crashes at precise moments

### Theoretical Attack Vectors

1. **Resource Exhaustion**: Attacker floods broker with messages, causing OOM crash during processing
2. **Exploit Chaining**: Combine with another vulnerability that causes crashes
3. **Network Partition**: In cluster mode, network issues may cause similar effects

## Impact Analysis

### Business Impact

**Financial Systems**:
- Duplicate payment processing
- Double debit/credit transactions
- Incorrect account balances

**IoT Control Systems**:
- Duplicate command execution (e.g., unlock door twice, start motor twice)
- Safety-critical operations repeated unexpectedly

**Message Billing**:
- Duplicate message charges
- Incorrect usage statistics

### Technical Impact

- **Protocol Violation**: Violates MQTT 3.1.1/5.0 specification for QoS 2
- **Data Integrity**: Subscribers receive duplicate messages
- **Idempotency Requirement**: Applications must implement their own deduplication

## Root Cause Analysis

The vulnerability stems from the design decision to prioritize **performance over correctness**:

1. **Current Implementation** (Fast but Unsafe):
   ```
   publish_message() → record_packet_id() → send_pubrec()
   ```
   - If crash occurs between step 1 and 2, duplication occurs

2. **Correct Implementation** (Slower but Safe):
   ```
   record_packet_id() → sync_commit() → publish_message() → send_pubrec()
   ```
   - If crash occurs after step 2, PacketId is already recorded
   - Retransmission will be rejected with PACKET_IDENTIFIER_IN_USE

## Recommended Fix

### Option 1: Reverse Operation Order (Recommended)

```erlang
% Memory Session
false ->
    % Step 1: Record PacketId first
    AwaitingRel1 = maps:put(PacketId, Ts, AwaitingRel),
    Session1 = Session#session{awaiting_rel = AwaitingRel1},
    % Step 2: Then publish message
    Results = emqx_broker:publish(Msg),
    {ok, Results, Session1};
```

**Trade-off**: If publish fails, need to clean up PacketId (acceptable)

### Option 2: Synchronous Commit for Persistent Sessions

```erlang
% Persistent Session
undefined ->
    S1 = emqx_persistent_session_ds_state:put_awaiting_rel(PacketId, TS, S0),
    ok = sync_commit_state(S1),  % Wait for commit
    Results = emqx_broker:publish(Msg),
    {ok, Results, Session#{s := S1}};
```

### Option 3: Transactional Approach

Wrap both operations in a transaction that can be rolled back on failure.

## Workarounds

For users unable to upgrade:

1. **Application-Level Deduplication**: Implement message deduplication using message IDs
2. **Idempotent Operations**: Design all operations to be safely repeatable
3. **High Availability**: Use clustered deployment with proper session persistence
4. **Monitoring**: Alert on broker crashes and investigate duplicate messages

## References

- MQTT 3.1.1 Specification: Section 4.3.3 (QoS 2: Exactly once delivery)
- EMQX Source Code: `apps/emqx/src/emqx_session_mem.erl`
- EMQX Source Code: `apps/emqx/src/emqx_persistent_session_ds.erl`

## Timeline

- **Discovery Date**: 2025-01-XX
- **Vendor Notification**: 2025-01-XX
- **Vendor Response**: Pending
- **Public Disclosure**: TBD (30-90 days after vendor notification)

## Credit

Reported by: [Your Name/Organization]
