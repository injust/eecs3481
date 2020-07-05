import java.math.BigInteger;

public class RSA {
	private BigInteger p, q, n, phi, e, d;

	/**
	 * ================================================================================
	 * Accessors and mutators
	 * ================================================================================
	 */

	public BigInteger p() {
		return p;
	}

	public void p(BigInteger p) {
		if (!p.equals(this.p)) {
			if (this.p != null) {
				throw new RuntimeException();
			}
			this.p = p;
			p_q_n__p_q_n();
			p_q_phi__p_q_phi();
		}
	}

	public BigInteger q() {
		return q;
	}

	public void q(BigInteger q) {
		if (!q.equals(this.q)) {
			if (this.q != null) {
				throw new RuntimeException();
			}
			this.q = q;
			p_q_n__p_q_n();
			p_q_phi__p_q_phi();
		}
	}

	/**
	 * @return Modulus: p * q
	 */
	public BigInteger n() {
		return n;
	}

	/**
	 * @param n Modulus: p * q
	 */
	public void n(BigInteger n) {
		if (!n.equals(this.n)) {
			if (this.n != null) {
				throw new RuntimeException();
			}
			this.n = n;
			p_q_n__p_q_n();
		}
	}

	/**
	 * @return (p - 1) * (q - 1)
	 */
	public BigInteger phi() {
		return phi;
	}

	/**
	 * @param phi (p - 1) * (q - 1)
	 */
	public void phi(BigInteger phi) {
		if (!phi.equals(this.phi)) {
			if (this.phi != null) {
				throw new RuntimeException();
			}
			this.phi = phi;
			p_q_phi__p_q_phi();
			e_phi__d();
		}
	}

	/**
	 * @return Public exponent
	 */
	public BigInteger e() {
		return e;
	}

	/**
	 * @param e Public exponent
	 */
	public void e(BigInteger e) {
		if (!e.equals(this.e)) {
			if (this.e != null) {
				throw new RuntimeException();
			}
			this.e = e;
			e_phi__d();
		}
	}

	/**
	 * @return Private exponent
	 */
	public BigInteger d() {
		return d;
	}

	/**
	 * @param d Private exponent
	 */
	public void d(BigInteger d) {
		if (!d.equals(this.d)) {
			if (this.d != null) {
				throw new RuntimeException();
			}
			this.d = d;
		}
	}

	/**
	 * ================================================================================
	 * Relations
	 * ================================================================================
	 */

	private void p_q_phi__p_q_phi() {
		if (p != null && phi != null) {
			// q = (p - 1) / phi + 1
			q(phi.divide(p.subtract(BigInteger.ONE)).add(BigInteger.ONE));
		} else if (p != null && q != null) {
			// phi = (p - 1) * (q - 1)
			phi(p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE)));
		} else if (phi != null && q != null) {
			// p = (q - 1) / phi + 1
			p(phi.divide(q.subtract(BigInteger.ONE)).add(BigInteger.ONE));
		}
	}

	private void p_q_n__p_q_n() {
		if (p != null && n != null) {
			// q = n / p
			q(n.divide(p));
		} else if (p != null && q != null) {
			// n = p * q
			n(p.multiply(q));
		} else if (n != null && q != null) {
			// p = n / q
			p(n.divide(q));
		}
	}

	private void e_phi__d() {
		if (e != null && phi != null) {
			// d * e ≡ 1 (mod phi)
			d(e.modInverse(phi));
		}
	}

	/**
	 * ================================================================================
	 * Encryption and decryption
	 * ================================================================================
	 */

	public BigInteger encrypt(BigInteger pt) {
		return pt.modPow(e, n);
	}

	public BigInteger decrypt(BigInteger ct) {
		return ct.modPow(d, n);
	}
}
