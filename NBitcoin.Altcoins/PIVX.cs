using NBitcoin;
using NBitcoin.DataEncoders;
using System.Reflection;
using NBitcoin.Protocol;
using NBitcoin.RPC;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;

namespace NBitcoin.Altcoins
{
	public class PIVX : NetworkSetBase
	{
		public static PIVX Instance { get; } = new PIVX();

		public override string CryptoCode => "PIVX";

		private PIVX()
		{

		}
		//Format visual studio
		//{({.*?}), (.*?)}
		//Tuple.Create(new byte[]$1, $2)
		static Tuple<byte[], int>[] pnSeed6_main =
			{

			};
		static Tuple<byte[], int>[] pnSeed6_test =
			{

			};

#pragma warning disable CS0618 // Type or member is obsolete
		public class PIVXConsensusFactory : ConsensusFactory
		{
			private PIVXConsensusFactory()
			{
			}

			public static PIVXConsensusFactory Instance { get; } = new PIVXConsensusFactory();

			public override Transaction CreateTransaction()
			{
				return new PIVXTransaction();
			}
			public override BlockHeader CreateBlockHeader()
			{
				return new PIVXBlockHeader();
			}
			public override Block CreateBlock()
			{
				return new PIVXBlock(new PIVXBlockHeader());
			}
		}


		public class PIVXTransaction : Transaction
		{
			public PIVXTransaction()
			{

			}
			public override ConsensusFactory GetConsensusFactory()
			{
				return PIVXConsensusFactory.Instance;
			}
			public override void ReadWrite(BitcoinStream stream)
			{
				var witSupported = (((uint)stream.TransactionOptions & (uint)TransactionOptions.Witness) != 0) &&
									stream.ProtocolCapabilities.SupportWitness;

				//var mwebSupported = false; //when mweb is supported in nbitcoin this is to be fixed

				byte flags = 0;
				if (!stream.Serializing)
				{
					stream.ReadWrite(ref nVersion);
					/* Try to read the vin. In case the dummy is there, this will be read as an empty vector. */
					stream.ReadWrite(ref vin);
					vin.Transaction = this;
					var hasNoDummy = (nVersion & NoDummyInput) != 0 && vin.Count == 0;
					if (witSupported && hasNoDummy)
						nVersion = nVersion & ~NoDummyInput;

					if (vin.Count == 0 && witSupported && !hasNoDummy)
					{
						/* We read a dummy or an empty vin. */
						stream.ReadWrite(ref flags);
						if (flags != 0)
						{
							/* Assume we read a dummy and a flag. */
							stream.ReadWrite(ref vin);
							vin.Transaction = this;
							stream.ReadWrite(ref vout);
							vout.Transaction = this;
						}
						else
						{
							/* Assume read a transaction without output. */
							vout = new TxOutList();
							vout.Transaction = this;
						}
					}
					else
					{
						/* We read a non-empty vin. Assume a normal vout follows. */
						stream.ReadWrite(ref vout);
						vout.Transaction = this;
					}
					if (((flags & 1) != 0) && witSupported)
					{
						/* The witness flag is present, and we support witnesses. */
						flags ^= 1;
						Witness wit = new Witness(Inputs);
						wit.ReadWrite(stream);
					}
					if ((flags & 8) != 0) //MWEB extension tx flag
					{
						/* The MWEB flag is present, but currently no MWEB data is supported.
						 * This fix just prevent from throwing exception bellow so cannonical PIVX transaction can be read
						 */
						flags ^= 8;
					}

					if (flags != 0)
					{
						/* Unknown flag in the serialization */
						throw new FormatException("Unknown transaction optional data");
					}
				}
				else
				{
					var version = (witSupported && (vin.Count == 0 && vout.Count > 0)) ? nVersion | NoDummyInput : nVersion;
					stream.ReadWrite(ref version);

					if (witSupported)
					{
						/* Check whether witnesses need to be serialized. */
						if (HasWitness)
						{
							flags |= 1;
						}
					}
					if (flags != 0)
					{
						/* Use extended format in case witnesses are to be serialized. */
						TxInList vinDummy = new TxInList();
						stream.ReadWrite(ref vinDummy);
						stream.ReadWrite(ref flags);
					}
					stream.ReadWrite(ref vin);
					vin.Transaction = this;
					stream.ReadWrite(ref vout);
					vout.Transaction = this;
					if ((flags & 1) != 0)
					{
						Witness wit = new Witness(this.Inputs);
						wit.ReadWrite(stream);
					}
				}
				stream.ReadWriteStruct(ref nLockTime);
			}
		}

		public class PIVXBlockHeader : BlockHeader
		{
			public override uint256 GetPoWHash()
			{
				var headerBytes = this.ToBytes();
				var h = NBitcoin.Crypto.SCrypt.ComputeDerivedKey(headerBytes, headerBytes, 1024, 1, 1, null, 32);
				return new uint256(h);
			}
		}

		public class PIVXBlock : Block
		{
			public PIVXBlock(PIVXBlockHeader header) : base(header)
			{

			}
			public override ConsensusFactory GetConsensusFactory()
			{
				return PIVXConsensusFactory.Instance;
			}
		}

		public class PIVXMainnetAddressStringParser : NetworkStringParser
		{
			public override bool TryParse(string str, Network network, Type targetType, out IBitcoinString result)
			{
				if(str.StartsWith("Ltpv", StringComparison.OrdinalIgnoreCase) && targetType.GetTypeInfo().IsAssignableFrom(typeof(BitcoinExtKey).GetTypeInfo()))
				{
					try
					{
						var decoded = Encoders.Base58Check.DecodeData(str);
						decoded[0] = 0x04;
						decoded[1] = 0x88;
						decoded[2] = 0xAD;
						decoded[3] = 0xE4;
						result = new BitcoinExtKey(Encoders.Base58Check.EncodeData(decoded), network);
						return true;
					}
					catch
					{
					}
				}
				if(str.StartsWith("Ltub", StringComparison.OrdinalIgnoreCase) && targetType.GetTypeInfo().IsAssignableFrom(typeof(BitcoinExtPubKey).GetTypeInfo()))
				{
					try
					{
						var decoded = Encoders.Base58Check.DecodeData(str);
						decoded[0] = 0x04;
						decoded[1] = 0x88;
						decoded[2] = 0xB2;
						decoded[3] = 0x1E;
						result = new BitcoinExtPubKey(Encoders.Base58Check.EncodeData(decoded), network);
						return true;
					}
					catch
					{
					}
				}
				return base.TryParse(str, network, targetType, out result);
			}
		}

		public class PIVXTestnetAddressStringParser : NetworkStringParser
		{
			public override bool TryParse(string str, Network network, Type targetType, out IBitcoinString result)
			{
				if (str.StartsWith("ttpv", StringComparison.OrdinalIgnoreCase) && targetType.GetTypeInfo().IsAssignableFrom(typeof(BitcoinExtKey).GetTypeInfo()))
				{
					try
					{
						var decoded = Encoders.Base58Check.DecodeData(str);
						decoded[0] = 0x04;
						decoded[1] = 0x35;
						decoded[2] = 0x83;
						decoded[3] = 0x94;
						result = new BitcoinExtKey(Encoders.Base58Check.EncodeData(decoded), network);
						return true;
					}
					catch
					{
					}
				}
				if (str.StartsWith("ttub", StringComparison.OrdinalIgnoreCase) && targetType.GetTypeInfo().IsAssignableFrom(typeof(BitcoinExtPubKey).GetTypeInfo()))
				{
					try
					{
						var decoded = Encoders.Base58Check.DecodeData(str);
						decoded[0] = 0x04;
						decoded[1] = 0x35;
						decoded[2] = 0x87;
						decoded[3] = 0xCF;
						result = new BitcoinExtPubKey(Encoders.Base58Check.EncodeData(decoded), network);
						return true;
					}
					catch
					{
					}
				}
				return base.TryParse(str, network, targetType, out result);
			}
		}

#pragma warning restore CS0618 // Type or member is obsolete

		protected override void PostInit()
		{
			RegisterDefaultCookiePath("PIVX", new FolderName() { TestnetFolder = "testnet4" });
		}

		protected override NetworkBuilder CreateMainnet()
		{
			var bech32 = Encoders.Bech32("PIVX");
			NetworkBuilder builder = new NetworkBuilder();
			builder.SetConsensus(new Consensus()
			{
				SubsidyHalvingInterval = 840000,
				MajorityEnforceBlockUpgrade = 750,
				MajorityRejectBlockOutdated = 950,
				MajorityWindow = 1000,
				BIP34Hash = new uint256("fa09d204a83a768ed5a7c8d441fa62f2043abf420cff1226c7b4329aeb9d51cf"),
				PowLimit = new Target(new uint256("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")),
				PowTargetTimespan = TimeSpan.FromSeconds(3.5 * 24 * 60 * 60),
				PowTargetSpacing = TimeSpan.FromSeconds(2.5 * 60),
				PowAllowMinDifficultyBlocks = false,
				PowNoRetargeting = false,
				RuleChangeActivationThreshold = 6048,
				MinerConfirmationWindow = 8064,
				CoinbaseMaturity = 100,
				PIVXWorkCalculation = true,
				ConsensusFactory = PIVXConsensusFactory.Instance,
				SupportSegwit = true,
				SupportTaproot = true
			})
			.SetBase58Bytes(Base58Type.PUBKEY_ADDRESS, new byte[] { 48 })
			.SetBase58Bytes(Base58Type.SCRIPT_ADDRESS, new byte[] { 50 })
			.SetBase58Bytes(Base58Type.SECRET_KEY, new byte[] { 176 })
			.SetBase58Bytes(Base58Type.EXT_PUBLIC_KEY, new byte[] { 0x04, 0x88, 0xB2, 0x1E })
			.SetBase58Bytes(Base58Type.EXT_SECRET_KEY, new byte[] { 0x04, 0x88, 0xAD, 0xE4 })
			.SetNetworkStringParser(new PIVXMainnetAddressStringParser())
			.SetBech32(Bech32Type.WITNESS_PUBKEY_ADDRESS, bech32)
			.SetBech32(Bech32Type.WITNESS_SCRIPT_ADDRESS, bech32)
			.SetBech32(Bech32Type.TAPROOT_ADDRESS, bech32)
			.SetMagic(0xdbb6c0fb)
			.SetPort(9333)
			.SetRPCPort(9332)
			.SetName("PIVX-main")
			.AddAlias("PIVX-mainnet")
			.AddAlias("PIVX-mainnet")
			.AddAlias("PIVX-main")
			.SetUriScheme("PIVX")
			.AddDNSSeeds(new[]
			{
				// new DNSSeedData("loshan.co.uk", "seed-a.litecoin.loshan.co.uk"),
				// new DNSSeedData("thrasher.io", "dnsseed.thrasher.io"),
				// new DNSSeedData("litecointools.com", "dnsseed.litecointools.com"),
				// new DNSSeedData("litecoinpool.org", "dnsseed.litecoinpool.org"),
				// new DNSSeedData("koin-project.com", "dnsseed.koin-project.com"),
			})
			.AddSeeds(ToSeed(pnSeed6_main))
			.SetGenesis("010000000000000000000000000000000000000000000000000000000000000000000000d9ced4ed1130f7b7faad9be25323ffafa33232a17c3edf6cfd97bee6bafbdd97b9aa8e4ef0ff0f1ecd513f7c0101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4804ffff001d0104404e592054696d65732030352f4f63742f32303131205374657665204a6f62732c204170706c65e280997320566973696f6e6172792c2044696573206174203536ffffffff0100f2052a010000004341040184710fa689ad5023690c80f3a49c8f13f8d45b8c857fbcbc8bc4a8e4d3eb4b10f4d4604fa08dce601aaf0f470216fe1b51850b4acf21b179c45070ac7b03a9ac00000000");
			return builder;
		}

		protected override NetworkBuilder CreateTestnet()
		{
			var bech32 = Encoders.Bech32("tPIVX");
			var builder = new NetworkBuilder();
			builder.SetConsensus(new Consensus()
			{
				SubsidyHalvingInterval = 840000,
				MajorityEnforceBlockUpgrade = 51,
				MajorityRejectBlockOutdated = 75,
				MajorityWindow = 1000,
				PowLimit = new Target(new uint256("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")),
				PowTargetTimespan = TimeSpan.FromSeconds(3.5 * 24 * 60 * 60),
				PowTargetSpacing = TimeSpan.FromSeconds(2.5 * 60),
				PowAllowMinDifficultyBlocks = true,
				PowNoRetargeting = false,
				RuleChangeActivationThreshold = 1512,
				MinerConfirmationWindow = 2016,
				CoinbaseMaturity = 100,
				PIVXWorkCalculation = true,
				ConsensusFactory = PIVXConsensusFactory.Instance,
				SupportSegwit = true,
				SupportTaproot = true
			})
			.SetBase58Bytes(Base58Type.PUBKEY_ADDRESS, new byte[] { 111 })
			.SetBase58Bytes(Base58Type.SCRIPT_ADDRESS, new byte[] { 58 })
			.SetBase58Bytes(Base58Type.SECRET_KEY, new byte[] { 239 })
			.SetBase58Bytes(Base58Type.EXT_PUBLIC_KEY, new byte[] { 0x04, 0x35, 0x87, 0xCF })
			.SetBase58Bytes(Base58Type.EXT_SECRET_KEY, new byte[] { 0x04, 0x35, 0x83, 0x94 })
			.SetNetworkStringParser(new PIVXTestnetAddressStringParser())
			.SetBech32(Bech32Type.WITNESS_PUBKEY_ADDRESS, bech32)
			.SetBech32(Bech32Type.WITNESS_SCRIPT_ADDRESS, bech32)
			.SetBech32(Bech32Type.TAPROOT_ADDRESS, bech32)
			.SetMagic(0xf1c8d2fd)
			.SetPort(19335)
			.SetRPCPort(19332)
			.SetName("PIVX-test")
			.AddAlias("PIVX-testnet")
			.AddAlias("PIVX-test")
			.AddAlias("PIVX-testnet")
			.SetUriScheme("PIVX")
			.AddDNSSeeds(new[]
			{
				// new DNSSeedData("litecointools.com", "testnet-seed.litecointools.com"),
				// new DNSSeedData("loshan.co.uk", "seed-b.litecoin.loshan.co.uk"),
				// new DNSSeedData("thrasher.io", "dnsseed-testnet.thrasher.io"),
			})
			.AddSeeds(ToSeed(pnSeed6_test))
			.SetGenesis("010000000000000000000000000000000000000000000000000000000000000000000000d9ced4ed1130f7b7faad9be25323ffafa33232a17c3edf6cfd97bee6bafbdd97f60ba158f0ff0f1ee17904000101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4804ffff001d0104404e592054696d65732030352f4f63742f32303131205374657665204a6f62732c204170706c65e280997320566973696f6e6172792c2044696573206174203536ffffffff0100f2052a010000004341040184710fa689ad5023690c80f3a49c8f13f8d45b8c857fbcbc8bc4a8e4d3eb4b10f4d4604fa08dce601aaf0f470216fe1b51850b4acf21b179c45070ac7b03a9ac00000000");
			return builder;
		}

		protected override NetworkBuilder CreateRegtest()
		{
			var bech32 = Encoders.Bech32();
			var builder = new NetworkBuilder();
			builder.SetConsensus(new Consensus()
			{
				SubsidyHalvingInterval = 150,
				MajorityEnforceBlockUpgrade = 51,
				MajorityRejectBlockOutdated = 75,
				MajorityWindow = 144,
				PowLimit = new Target(new uint256("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")),
				PowTargetTimespan = TimeSpan.FromSeconds(3.5 * 24 * 60 * 60),
				PowTargetSpacing = TimeSpan.FromSeconds(2.5 * 60),
				PowAllowMinDifficultyBlocks = true,
				MinimumChainWork = uint256.Zero,
				PowNoRetargeting = true,
				RuleChangeActivationThreshold = 108,
				MinerConfirmationWindow = 2016,
				CoinbaseMaturity = 100,
				PIVXWorkCalculation = true,
				ConsensusFactory = PIVXConsensusFactory.Instance,
				SupportSegwit = true,
				SupportTaproot = true
			})
			.SetBase58Bytes(Base58Type.PUBKEY_ADDRESS, new byte[] { 111 })
			.SetBase58Bytes(Base58Type.SCRIPT_ADDRESS, new byte[] { 58 })
			.SetBase58Bytes(Base58Type.SECRET_KEY, new byte[] { 239 })
			.SetBase58Bytes(Base58Type.EXT_PUBLIC_KEY, new byte[] { 0x04, 0x35, 0x87, 0xCF })
			.SetBase58Bytes(Base58Type.EXT_SECRET_KEY, new byte[] { 0x04, 0x35, 0x83, 0x94 })
			.SetBech32(Bech32Type.WITNESS_PUBKEY_ADDRESS, bech32)
			.SetBech32(Bech32Type.WITNESS_SCRIPT_ADDRESS, bech32)
			.SetBech32(Bech32Type.TAPROOT_ADDRESS, bech32)
			.SetMagic(0xdab5bffa)
			.SetPort(19444)
			.SetRPCPort(19443)
			.SetName("PIVX-reg")
			.AddAlias("PIVX-regtest")
			.AddAlias("PIVX-reg")
			.AddAlias("PIVX-regtest")
			.SetUriScheme("PIVX")
			.SetGenesis("010000000000000000000000000000000000000000000000000000000000000000000000d9ced4ed1130f7b7faad9be25323ffafa33232a17c3edf6cfd97bee6bafbdd97dae5494dffff7f20000000000101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4804ffff001d0104404e592054696d65732030352f4f63742f32303131205374657665204a6f62732c204170706c65e280997320566973696f6e6172792c2044696573206174203536ffffffff0100f2052a010000004341040184710fa689ad5023690c80f3a49c8f13f8d45b8c857fbcbc8bc4a8e4d3eb4b10f4d4604fa08dce601aaf0f470216fe1b51850b4acf21b179c45070ac7b03a9ac00000000");
			return builder;
		}
	}
}
