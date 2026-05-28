import type { MarmotGroup } from "@internet-privacy/marmot-ts/client";
import { Proposals } from "@internet-privacy/marmot-ts/client";
import { getOwnLeafNode } from "ts-mls";

declare const group: MarmotGroup;

// AC-PKG-3: verify that ClientState from marmot-ts and ts-mls are the same branded type.
// Before the peer-dep fix this produced TS2345 due to duplicate ts-mls module instances.
getOwnLeafNode(group.state);

// Verify ProposalAction compatibility: ProposalRemove from marmot-ts must unify with
// the Proposal type expected by MarmotGroup.propose().
void group.propose(Proposals.proposeRemoveUser("deadbeef"));
