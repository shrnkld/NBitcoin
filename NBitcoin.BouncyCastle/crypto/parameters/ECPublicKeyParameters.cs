using System;
using System.Globalization;

using NBitcoin.BouncyCastle.Asn1;
using NBitcoin.BouncyCastle.Math.EC;

namespace NBitcoin.BouncyCastle.Crypto.Parameters
{
    public class ECPublicKeyParameters
        : ECKeyParameters
    {
        private readonly ECPoint q;

        public ECPublicKeyParameters(
            ECPoint				q,
            ECDomainParameters	parameters)
            : this("EC", q, parameters)
        {
        }

        public ECPublicKeyParameters(
            string				algorithm,
            ECPoint				q,
            ECDomainParameters	parameters)
            : base(algorithm, false, parameters)
        {
            if (q == null)
                throw new ArgumentNullException("q");

            this.q = q.Normalize();
        }

        public ECPoint Q
        {
            get { return q; }
        }

        public override bool Equals(object obj)
        {
            if (obj == this)
                return true;

            ECPublicKeyParameters other = obj as ECPublicKeyParameters;

            if (other == null)
                return false;

            return Equals(other);
        }

        protected bool Equals(
            ECPublicKeyParameters other)
        {
            return q.Equals(other.q) && base.Equals(other);
        }

        public override int GetHashCode()
        {
            return q.GetHashCode() ^ base.GetHashCode();
        }
    }
}
