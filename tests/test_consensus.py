"""
Tests for Agentic AI Consensus Module
======================================

Unit tests for consensus-based decision making.
"""

import pytest
from agentic_ai.consensus.proposal import ProposalStatus as _ProposalStatus

# Make ProposalStatus available at module level for tests that reference it directly
ProposalStatus = _ProposalStatus


@pytest.fixture
def consensus_imports():
    """Import consensus modules."""
    from agentic_ai.consensus.engine import ConsensusEngine
    from agentic_ai.consensus.proposal import (
        Proposal, Vote, VoteOption, ConsensusType,
        ProposalStatus, ConsensusResult
    )
    return {
        'ConsensusEngine': ConsensusEngine,
        'Proposal': Proposal,
        'Vote': Vote,
        'VoteOption': VoteOption,
        'ConsensusType': ConsensusType,
        'ProposalStatus': ProposalStatus,
        'ConsensusResult': ConsensusResult,
    }


class TestVote:
    """Test Vote class."""
    
    def test_vote_creation(self, consensus_imports):
        """Test creating a vote."""
        Vote = consensus_imports['Vote']
        VoteOption = consensus_imports['VoteOption']
        
        vote = Vote(
            proposal_id="prop-001",
            voter_id="agent-001",
            option=VoteOption.APPROVE,
            rationale="Looks good to me",
        )
        
        assert vote.proposal_id == "prop-001"
        assert vote.voter_id == "agent-001"
        assert vote.option == VoteOption.APPROVE
        assert vote.rationale == "Looks good to me"
        assert vote.weight == 1.0
        assert vote.vote_id is not None
    
    def test_vote_weighted(self, consensus_imports):
        """Test weighted vote."""
        Vote = consensus_imports['Vote']
        VoteOption = consensus_imports['VoteOption']
        
        vote = Vote(
            proposal_id="prop-001",
            voter_id="lead-agent",
            option=VoteOption.APPROVE,
            weight=2.0,
        )
        
        assert vote.weight == 2.0
    
    def test_vote_to_dict(self, consensus_imports):
        """Test vote serialization."""
        Vote = consensus_imports['Vote']
        VoteOption = consensus_imports['VoteOption']
        
        vote = Vote(
            proposal_id="prop-001",
            voter_id="agent-001",
            option=VoteOption.APPROVE,
        )
        
        data = vote.to_dict()
        
        assert data["proposal_id"] == "prop-001"
        assert data["voter_id"] == "agent-001"
        assert data["option"] == "approve"
        assert "vote_id" in data
    
    def test_vote_from_dict(self, consensus_imports):
        """Test vote deserialization."""
        Vote = consensus_imports['Vote']
        VoteOption = consensus_imports['VoteOption']
        
        data = {
            "vote_id": "vote-001",
            "proposal_id": "prop-001",
            "voter_id": "agent-001",
            "option": "reject",
            "rationale": "Has issues",
        }
        
        vote = Vote.from_dict(data)
        
        assert vote.vote_id == "vote-001"
        assert vote.option == VoteOption.REJECT
        assert vote.rationale == "Has issues"


class TestProposal:
    """Test Proposal class."""
    
    def test_proposal_creation(self, consensus_imports):
        """Test creating a proposal."""
        Proposal = consensus_imports['Proposal']
        ConsensusType = consensus_imports['ConsensusType']
        
        proposal = Proposal(
            title="Add new feature",
            description="Implement multi-agent conversations",
            proposer_id="lead-001",
            consensus_type=ConsensusType.MAJORITY,
        )
        
        assert proposal.title == "Add new feature"
        assert proposal.proposer_id == "lead-001"
        assert proposal.consensus_type == ConsensusType.MAJORITY
        assert proposal.status == ProposalStatus.DRAFT
        assert len(proposal.votes) == 0
    
    def test_add_vote(self, consensus_imports):
        """Test adding votes to proposal."""
        Proposal = consensus_imports['Proposal']
        Vote = consensus_imports['Vote']
        VoteOption = consensus_imports['VoteOption']
        
        proposal = Proposal(title="Test", description="Test", proposer_id="agent-001")
        
        vote1 = Vote(proposal_id=proposal.proposal_id, voter_id="agent-001", option=VoteOption.APPROVE)
        vote2 = Vote(proposal_id=proposal.proposal_id, voter_id="agent-002", option=VoteOption.REJECT)
        
        proposal.add_vote(vote1)
        proposal.add_vote(vote2)
        
        assert len(proposal.votes) == 2
        assert proposal.get_vote_count(VoteOption.APPROVE) == 1
        assert proposal.get_vote_count(VoteOption.REJECT) == 1
    
    def test_approval_rate(self, consensus_imports):
        """Test approval rate calculation."""
        Proposal = consensus_imports['Proposal']
        Vote = consensus_imports['Vote']
        VoteOption = consensus_imports['VoteOption']
        
        proposal = Proposal(title="Test", description="Test", proposer_id="agent-001")
        
        # 3 approve, 1 reject
        for i in range(3):
            proposal.add_vote(Vote(proposal_id=proposal.proposal_id, voter_id=f"agent-{i}", option=VoteOption.APPROVE))
        proposal.add_vote(Vote(proposal_id=proposal.proposal_id, voter_id="agent-4", option=VoteOption.REJECT))
        
        assert proposal.get_approval_rate() == 0.75
    
    def test_participation_rate(self, consensus_imports):
        """Test participation rate calculation."""
        Proposal = consensus_imports['Proposal']
        Vote = consensus_imports['Vote']
        VoteOption = consensus_imports['VoteOption']
        
        proposal = Proposal(
            title="Test",
            description="Test",
            proposer_id="agent-001",
            eligible_voters=["agent-001", "agent-002", "agent-003", "agent-004"],
        )
        
        # 2 out of 4 voted
        proposal.add_vote(Vote(proposal_id=proposal.proposal_id, voter_id="agent-001", option=VoteOption.APPROVE))
        proposal.add_vote(Vote(proposal_id=proposal.proposal_id, voter_id="agent-002", option=VoteOption.APPROVE))
        
        assert proposal.get_participation_rate() == 0.5
    
    def test_start_voting(self, consensus_imports):
        """Test starting voting period."""
        Proposal = consensus_imports['Proposal']
        
        proposal = Proposal(title="Test", description="Test", proposer_id="agent-001")
        
        assert proposal.status == ProposalStatus.DRAFT
        
        proposal.start_voting(duration_minutes=30)
        
        assert proposal.status == ProposalStatus.VOTING
        assert proposal.voting_started_at is not None
        assert proposal.voting_ends_at is not None
    
    def test_withdraw_proposal(self, consensus_imports):
        """Test withdrawing a proposal."""
        Proposal = consensus_imports['Proposal']
        
        proposal = Proposal(title="Test", description="Test", proposer_id="agent-001")
        
        proposal.withdraw()
        
        assert proposal.status == ProposalStatus.WITHDRAWN
        assert proposal.completed_at is not None


class TestConsensusEngine:
    """Test ConsensusEngine class."""
    
    def test_create_proposal(self, consensus_imports):
        """Test creating a proposal via engine."""
        ConsensusEngine = consensus_imports['ConsensusEngine']
        ConsensusType = consensus_imports['ConsensusType']
        
        engine = ConsensusEngine()
        
        proposal = engine.create_proposal(
            title="Deploy to production",
            description="Deploy version 2.0",
            proposer_id="lead-001",
            consensus_type=ConsensusType.SUPERMAJORITY,
            eligible_voters=["dev-001", "dev-002", "qa-001"],
        )
        
        assert proposal.title == "Deploy to production"
        assert proposal.consensus_type == ConsensusType.SUPERMAJORITY
        assert len(proposal.eligible_voters) == 3
        assert proposal.proposal_id in engine.proposals
    
    def test_submit_proposal(self, consensus_imports):
        """Test submitting a proposal."""
        ConsensusEngine = consensus_imports['ConsensusEngine']
        
        engine = ConsensusEngine()
        proposal = engine.create_proposal("Test", "Test", "agent-001")
        
        result = engine.submit_proposal(proposal.proposal_id)
        
        assert result is True
        assert proposal.status == ProposalStatus.ACTIVE
    
    def test_start_voting(self, consensus_imports):
        """Test starting voting."""
        ConsensusEngine = consensus_imports['ConsensusEngine']
        
        engine = ConsensusEngine()
        proposal = engine.create_proposal("Test", "Test", "agent-001")
        engine.submit_proposal(proposal.proposal_id)
        
        result = engine.start_voting(proposal.proposal_id, duration_minutes=60)
        
        assert result is True
        assert proposal.status == ProposalStatus.VOTING
    
    def test_cast_vote(self, consensus_imports):
        """Test casting a vote."""
        ConsensusEngine = consensus_imports['ConsensusEngine']
        VoteOption = consensus_imports['VoteOption']
        
        engine = ConsensusEngine()
        proposal = engine.create_proposal(
            "Test", "Test", "agent-001",
            eligible_voters=["agent-001", "agent-002"]
        )
        engine.submit_proposal(proposal.proposal_id)
        engine.start_voting(proposal.proposal_id)
        
        vote = engine.cast_vote(
            proposal_id=proposal.proposal_id,
            voter_id="agent-001",
            option=VoteOption.APPROVE,
            rationale="Looks good",
        )
        
        assert vote is not None
        assert vote.option == VoteOption.APPROVE
        assert len(proposal.votes) == 1
    
    def test_vote_ineligible_voter(self, consensus_imports):
        """Test voting by ineligible voter."""
        ConsensusEngine = consensus_imports['ConsensusEngine']
        VoteOption = consensus_imports['VoteOption']
        
        engine = ConsensusEngine()
        proposal = engine.create_proposal(
            "Test", "Test", "agent-001",
            eligible_voters=["agent-001"]
        )
        engine.submit_proposal(proposal.proposal_id)
        engine.start_voting(proposal.proposal_id)
        
        vote = engine.cast_vote(
            proposal_id=proposal.proposal_id,
            voter_id="agent-002",  # Not eligible
            option=VoteOption.APPROVE,
        )
        
        assert vote is None
    
    def test_check_consensus_majority(self, consensus_imports):
        """Test majority consensus check."""
        ConsensusEngine = consensus_imports['ConsensusEngine']
        VoteOption = consensus_imports['VoteOption']
        ConsensusType = consensus_imports['ConsensusType']
        
        engine = ConsensusEngine()
        proposal = engine.create_proposal(
            "Test", "Test", "agent-001",
            consensus_type=ConsensusType.MAJORITY,
            eligible_voters=["agent-001", "agent-002", "agent-003"],
            quorum_requirement=0.5,
        )
        engine.submit_proposal(proposal.proposal_id)
        engine.start_voting(proposal.proposal_id)
        
        # 2 approve, 1 reject (66% approval > 50%)
        engine.cast_vote(proposal.proposal_id, "agent-001", VoteOption.APPROVE)
        engine.cast_vote(proposal.proposal_id, "agent-002", VoteOption.APPROVE)
        engine.cast_vote(proposal.proposal_id, "agent-003", VoteOption.REJECT)
        
        result = engine.check_consensus(proposal.proposal_id)
        
        assert result is not None
        assert result.passed is True
        assert result.approval_rate == pytest.approx(2/3)
    
    def test_check_consensus_unanimous(self, consensus_imports):
        """Test unanimous consensus check."""
        ConsensusEngine = consensus_imports['ConsensusEngine']
        VoteOption = consensus_imports['VoteOption']
        ConsensusType = consensus_imports['ConsensusType']
        
        engine = ConsensusEngine()
        proposal = engine.create_proposal(
            "Test", "Test", "agent-001",
            consensus_type=ConsensusType.UNANIMOUS,
            eligible_voters=["agent-001", "agent-002"],
        )
        engine.submit_proposal(proposal.proposal_id)
        engine.start_voting(proposal.proposal_id)
        
        # Both approve
        engine.cast_vote(proposal.proposal_id, "agent-001", VoteOption.APPROVE)
        engine.cast_vote(proposal.proposal_id, "agent-002", VoteOption.APPROVE)
        
        result = engine.check_consensus(proposal.proposal_id)
        
        assert result is not None
        assert result.passed is True
        assert result.approval_rate == 1.0
    
    def test_no_consensus_quorum_not_met(self, consensus_imports):
        """Test when quorum is not met."""
        ConsensusEngine = consensus_imports['ConsensusEngine']
        VoteOption = consensus_imports['VoteOption']
        
        engine = ConsensusEngine()
        proposal = engine.create_proposal(
            "Test", "Test", "agent-001",
            eligible_voters=["agent-001", "agent-002", "agent-003", "agent-004"],
            quorum_requirement=0.75,  # Need 75% participation
        )
        engine.submit_proposal(proposal.proposal_id)
        engine.start_voting(proposal.proposal_id)
        
        # Only 2 out of 4 voted (50% < 75%)
        engine.cast_vote(proposal.proposal_id, "agent-001", VoteOption.APPROVE)
        engine.cast_vote(proposal.proposal_id, "agent-002", VoteOption.APPROVE)
        
        result = engine.check_consensus(proposal.proposal_id)
        
        assert result is None  # No consensus yet
    
    def test_get_stats(self, consensus_imports):
        """Test getting consensus statistics."""
        ConsensusEngine = consensus_imports['ConsensusEngine']
        
        engine = ConsensusEngine()
        
        # Create 3 proposals
        engine.create_proposal("Test 1", "Test", "agent-001")
        engine.create_proposal("Test 2", "Test", "agent-001")
        proposal3 = engine.create_proposal("Test 3", "Test", "agent-001")
        
        engine.submit_proposal(proposal3.proposal_id)
        engine.start_voting(proposal3.proposal_id)
        
        stats = engine.get_stats()
        
        assert stats["total_proposals"] == 3
        assert stats["active_proposals"] == 1
        assert "by_status" in stats


class TestConsensusIntegration:
    """Integration tests for consensus."""
    
    def test_full_voting_workflow(self, consensus_imports):
        """Test complete voting workflow."""
        ConsensusEngine = consensus_imports['ConsensusEngine']
        VoteOption = consensus_imports['VoteOption']
        ConsensusType = consensus_imports['ConsensusType']
        
        engine = ConsensusEngine()
        
        # Create proposal
        proposal = engine.create_proposal(
            title="Deploy v2.0 to production",
            description="Release new version with conversation features",
            proposer_id="lead-001",
            consensus_type=ConsensusType.SUPERMAJORITY,
            eligible_voters=["dev-001", "dev-002", "qa-001", "ops-001"],
            quorum_requirement=0.75,
        )
        
        # Submit and start voting
        engine.submit_proposal(proposal.proposal_id)
        engine.start_voting(proposal.proposal_id, duration_minutes=60)
        
        # Cast votes
        engine.cast_vote(proposal.proposal_id, "dev-001", VoteOption.APPROVE, rationale="Ready")
        engine.cast_vote(proposal.proposal_id, "dev-002", VoteOption.APPROVE, rationale="Tests pass")
        engine.cast_vote(proposal.proposal_id, "qa-001", VoteOption.APPROVE, rationale="QA approved")
        engine.cast_vote(proposal.proposal_id, "ops-001", VoteOption.ABSTAIN, rationale="No opinion")
        
        # Check consensus
        result = engine.check_consensus(proposal.proposal_id)
        
        assert result is not None
        assert result.passed is True
        assert result.participation_rate == 1.0
        assert result.approval_rate == 1.0  # 3 approve, 1 abstain = 100% of non-abstain
        assert result.vote_summary["approve"] == 3
        assert result.vote_summary["abstain"] == 1
        
        # Verify proposal status updated
        assert proposal.status == ProposalStatus.PASSED
        assert proposal.completed_at is not None
    
    def test_weighted_voting(self, consensus_imports):
        """Test weighted voting."""
        ConsensusEngine = consensus_imports['ConsensusEngine']
        VoteOption = consensus_imports['VoteOption']
        ConsensusType = consensus_imports['ConsensusType']
        
        engine = ConsensusEngine()
        
        proposal = engine.create_proposal(
            title="Critical fix",
            description="Urgent security patch",
            proposer_id="lead-001",
            consensus_type=ConsensusType.WEIGHTED,
            eligible_voters=["lead-001", "dev-001", "dev-002"],
        )
        
        engine.submit_proposal(proposal.proposal_id)
        engine.start_voting(proposal.proposal_id)
        
        # Lead has 3x weight
        engine.cast_vote(proposal.proposal_id, "lead-001", VoteOption.APPROVE, weight=3.0)
        engine.cast_vote(proposal.proposal_id, "dev-001", VoteOption.REJECT, weight=1.0)
        engine.cast_vote(proposal.proposal_id, "dev-002", VoteOption.REJECT, weight=1.0)
        
        result = engine.check_consensus(proposal.proposal_id)
        
        assert result is not None
        assert result.passed is True  # 3 weight approve vs 2 weight reject
        assert result.weighted_approval_rate == 0.6  # 3/(3+1+1)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
