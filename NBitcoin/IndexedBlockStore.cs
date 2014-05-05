﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace NBitcoin
{
	public class IndexedBlockStore
	{
		private readonly NoSqlRepository _Index;
		private readonly BlockStore _Store;
		public IndexedBlockStore(NoSqlRepository index, BlockStore store)
		{
			if(index == null)
				throw new ArgumentNullException("index");
			if(store == null)
				throw new ArgumentNullException("store");
			_Index = index;
			_Store = store;
		}

		public void ReIndex()
		{
			int count = 0;
			foreach(var blocks in _Store.Enumerate(true).Partition(400))
			{
				count += blocks.Count;
				_Index.PutBatch(blocks.Select(b => new Tuple<String, IBitcoinSerializable>(b.Block.GetHash().ToString(), b.BlockPosition)));
			}
		}

		public Block Get(uint256 hash)
		{
			var pos = _Index.Get<DiskBlockPos>(hash.ToString());
			if(pos == null)
				return null;
			var stored = _Store.Enumerate(false, new DiskBlockPosRange(pos)).FirstOrDefault();
			if(stored == null)
				return null;
			return stored.Block;
		}
		public void Put(Block block)
		{
			var hash = block.Header.GetHash();
			var position = _Store.Append(block);
			_Index.Put(hash.ToString(), position);
		}

	}
}
