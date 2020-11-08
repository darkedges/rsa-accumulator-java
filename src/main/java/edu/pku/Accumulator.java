package edu.pku;

import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;

/**
 * @author Lei, HUANG (lhuang@pku.edu.cn): 2019-04-17 19:37:38
 */
public class Accumulator {

	private static int RSA_KEY_SIZE = 3072;
	private static int RSA_PRIME_SIZE = RSA_KEY_SIZE / 2;
	private static int ACCUMULATED_PRIME_SIZE = 128;
	private static BigInteger N;
	
	static {
		Pair<BigInteger> bigIntegerPair = Util.generateTwoLargeDistinctPrimes(RSA_PRIME_SIZE);
		BigInteger p = bigIntegerPair.getFirst();
		BigInteger q = bigIntegerPair.getSecond();
		N = p.multiply(q);
	}

	public BigInteger commitment;
	private BigInteger A0;
	final private EnhancedRandom random;
	final private Map<BigInteger, BigInteger> data;

	public Accumulator() {
		data = new HashMap<>();
		random = new EnhancedRandom();
		A0 = random.nextBigInteger(BigInteger.ZERO, N);
		commitment = A0;
	}

	/**
	 * get size of all accumulated elements
	 * 
	 * @return size of all accumulated elements
	 */
	public int size() {
		return data.size();
	}

	public BigInteger getN() {
		return N;
	}

	public BigInteger getNonce(BigInteger x) {
		return data.get(x);
	}

	public BigInteger add(BigInteger x) {
		if (data.containsKey(x)) {
			return commitment;
		} else {
			Pair<BigInteger> bigIntegerPair = Util.hashToPrime(x, ACCUMULATED_PRIME_SIZE);
			BigInteger hashPrime = bigIntegerPair.getFirst();
			BigInteger nonce = bigIntegerPair.getSecond();
			commitment = commitment.modPow(hashPrime, N);
			data.put(x, nonce);
			return commitment;
		}
	}

	public Pair<BigInteger> proveMembership(BigInteger x) {
		if (!data.containsKey(x)) {
			return null;
		} else {
			BigInteger product = iterateAndGetProduct(x);
			return new Pair<BigInteger>(A0.modPow(product, N),
					Util.hashToPrime(x, ACCUMULATED_PRIME_SIZE, getNonce(x)).getFirst());
		}
	}

	/**
	 * Iterate data map
	 *
	 * @param x
	 * @return
	 * @author Lei, HUANG (lhuang@pku.edu.cn): 2019-04-17 22:40:13
	 */
	private BigInteger iterateAndGetProduct(BigInteger x) {
		BigInteger product = BigInteger.ONE;
		for (BigInteger k : data.keySet()) {
			// calculate the product of nonce of elements except x itself
			if (k.compareTo(x) != 0) {
				BigInteger nonce = data.get(k);
				product = product.multiply(
						// only hashed value needed here
						Util.hashToPrime(k, ACCUMULATED_PRIME_SIZE, nonce).getFirst());
			}
		}
		return product;
	}

	/**
	 * delete an element from accumulator and return the updated value
	 *
	 * @param x ele to delete
	 * @return updated accumulator value
	 * @author Lei, HUANG (lhuang@pku.edu.cn): 2019-04-17 22:44:51
	 */
	public BigInteger delete(BigInteger x) {
		if (!data.containsKey(x)) {
			return commitment;
		} else {
			data.remove(x);
			final BigInteger product = iterateAndGetProduct(x);
			this.commitment = A0.modPow(product, N);
			return commitment;
		}
	}

	/**
	 * use simple modpow calculation to verify element membership
	 *
	 * @param A
	 * @param x
	 * @param proof
	 * @param n
	 * @return
	 * @author Lei, HUANG (lhuang@pku.edu.cn): 2019-04-17 22:45:02
	 */
	private static boolean doVerifyMembership(BigInteger A, BigInteger x, BigInteger proof) {
		return proof.modPow(x, N).compareTo(A) == 0;
	}

	/**
	 * verify element membership
	 *
	 * @param A
	 * @param x
	 * @param nonce
	 * @param proof
	 * @param n
	 * @return true if element x is accumulated by accumulator A, with proof,nonce
	 *         and
	 */
	public static boolean verifyMembership(BigInteger A, BigInteger x, BigInteger nonce, BigInteger proof,
			BigInteger n) {
		return doVerifyMembership(A, Util.hashToPrime(x, ACCUMULATED_PRIME_SIZE, nonce).getFirst(), proof);
	}

	public static boolean verifyMembership(BigInteger commitment, Pair<BigInteger> proof) {
		return doVerifyMembership(commitment, proof.getSecond(), proof.getFirst());
	}

	public static boolean verifyMembership(VerifyRequest verifyRequest) {
		return verifyMembership(verifyRequest.getCommitment(), verifyRequest.getProof());
	}
}
