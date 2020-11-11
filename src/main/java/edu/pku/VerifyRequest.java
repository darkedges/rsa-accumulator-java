package edu.pku;

import java.math.BigInteger;

public class VerifyRequest {
	private BigInteger commitment;
	private Pair<BigInteger> proof;

	public BigInteger getCommitment() {
		return commitment;
	}

	public void setCommitment(BigInteger commitment) {
		this.commitment = commitment;
	}

	public Pair<BigInteger> getProof() {
		return proof;
	}

	public void setProof(Pair<BigInteger> proof) {
		this.proof = proof;
	}
}
