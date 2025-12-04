#include "i486trace.h"
#include <sqlite3.h>
#include <chrono>
#include <sstream>

TraceRecorder::TraceRecorder()
{
}

TraceRecorder::~TraceRecorder()
{
	if (active)
	{
		Stop();
	}
}

bool TraceRecorder::Start(const std::string& dbPath, const Config& cfg)
{
	if (active)
	{
		return false;
	}

	config = cfg;
	seq = 0;
	totalInstructions = 0;
	instructionsSinceSnapshot = 0;
	memWriteCount = 0;
	memReadCount = 0;
	callCount = 0;
	retCount = 0;
	droppedEvents = 0;
	dbErrors = 0;
	insertsSinceCommit = 0;
	needsSnapshot = false;
	seenReadVals.clear();
	seenWriteVals.clear();
	seenCalls.clear();
	seenRets.clear();
	readCount.clear();
	writeCount.clear();

	if (!InitDatabase(dbPath))
	{
		return false;
	}

	if (!PrepareStatements())
	{
		sqlite3_close(db);
		db = nullptr;
		return false;
	}

	BeginTransaction();
	active = true;

	writerStop.store(false);
	writerThread = std::thread(&TraceRecorder::WriterThreadFunc, this);

	return true;
}

void TraceRecorder::Stop()
{
	if (!active)
	{
		return;
	}

	active = false;

	writerStop.store(true);
	if (writerThread.joinable())
	{
		writerThread.join();
	}

	CommitTransaction();
	FinalizeStatements();

	auto now = std::chrono::system_clock::now();
	auto timestamp = std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count();
	std::string sql = "INSERT OR REPLACE INTO meta(key, value) VALUES('capture_end_time', '" + std::to_string(timestamp) + "')";
	sqlite3_exec(db, sql.c_str(), nullptr, nullptr, nullptr);

	sql = "INSERT OR REPLACE INTO meta(key, value) VALUES('total_instructions', '" + std::to_string(totalInstructions) + "')";
	sqlite3_exec(db, sql.c_str(), nullptr, nullptr, nullptr);

	sqlite3_close(db);
	db = nullptr;
}

bool TraceRecorder::IsActive() const
{
	return active;
}

bool TraceRecorder::InitDatabase(const std::string& dbPath)
{
	int rc = sqlite3_open(dbPath.c_str(), &db);
	if (rc != SQLITE_OK)
	{
		return false;
	}

	// Performance tuning - aggressive settings for trace capture
	sqlite3_exec(db, "PRAGMA journal_mode = OFF", nullptr, nullptr, nullptr);  // No journal, single file
	sqlite3_exec(db, "PRAGMA synchronous = OFF", nullptr, nullptr, nullptr);   // Don't wait for disk
	sqlite3_exec(db, "PRAGMA locking_mode = EXCLUSIVE", nullptr, nullptr, nullptr);
	sqlite3_exec(db, "PRAGMA temp_store = MEMORY", nullptr, nullptr, nullptr);

	const char* schema = R"(
		CREATE TABLE IF NOT EXISTS meta (
			key TEXT PRIMARY KEY,
			value TEXT
		);

		CREATE TABLE IF NOT EXISTS mem_write (
			seq INTEGER PRIMARY KEY,
			pc INTEGER NOT NULL,
			addr INTEGER NOT NULL,
			size INTEGER NOT NULL,
			old_val INTEGER NOT NULL,
			new_val INTEGER NOT NULL
		);

		CREATE TABLE IF NOT EXISTS mem_read (
			seq INTEGER PRIMARY KEY,
			pc INTEGER NOT NULL,
			addr INTEGER NOT NULL,
			size INTEGER NOT NULL,
			val INTEGER NOT NULL
		);

		CREATE TABLE IF NOT EXISTS call (
			seq INTEGER PRIMARY KEY,
			pc INTEGER NOT NULL,
			target INTEGER NOT NULL,
			esp INTEGER NOT NULL,
			type INTEGER NOT NULL,
			int_num INTEGER NOT NULL DEFAULT 0
		);

		CREATE TABLE IF NOT EXISTS ret (
			seq INTEGER PRIMARY KEY,
			pc INTEGER NOT NULL,
			return_to INTEGER NOT NULL,
			esp INTEGER NOT NULL,
			type INTEGER NOT NULL
		);

		CREATE TABLE IF NOT EXISTS snapshot (
			seq INTEGER PRIMARY KEY,
			data BLOB NOT NULL
		);
	)";

	char* errMsg = nullptr;
	rc = sqlite3_exec(db, schema, nullptr, nullptr, &errMsg);
	if (rc != SQLITE_OK)
	{
		if (errMsg)
		{
			sqlite3_free(errMsg);
		}
		return false;
	}

	auto now = std::chrono::system_clock::now();
	auto timestamp = std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count();

	std::ostringstream metaSql;
	metaSql << "INSERT OR REPLACE INTO meta(key, value) VALUES"
			<< "('version', '1'),"
			<< "('capture_start_time', '" << timestamp << "'),"
			<< "('capture_mem_read', '" << (config.captureMemRead ? 1 : 0) << "'),"
			<< "('capture_mem_write', '" << (config.captureMemWrite ? 1 : 0) << "'),"
			<< "('capture_call', '" << (config.captureCall ? 1 : 0) << "'),"
			<< "('capture_ret', '" << (config.captureRet ? 1 : 0) << "'),"
			<< "('snapshot_interval', '" << config.snapshotInterval << "'),"
			<< "('adaptive_threshold', '" << config.adaptiveThreshold << "')";

	rc = sqlite3_exec(db, metaSql.str().c_str(), nullptr, nullptr, &errMsg);
	if (rc != SQLITE_OK)
	{
		if (errMsg)
		{
			sqlite3_free(errMsg);
		}
		return false;
	}

	return true;
}

bool TraceRecorder::PrepareStatements()
{
	int rc;

	rc = sqlite3_prepare_v2(db,
		"INSERT INTO mem_write(pc, addr, size, old_val, new_val) VALUES(?, ?, ?, ?, ?)",
		-1, &stmtMemWrite, nullptr);
	if (rc != SQLITE_OK) return false;

	rc = sqlite3_prepare_v2(db,
		"INSERT INTO mem_read(pc, addr, size, val) VALUES(?, ?, ?, ?)",
		-1, &stmtMemRead, nullptr);
	if (rc != SQLITE_OK) return false;

	rc = sqlite3_prepare_v2(db,
		"INSERT INTO call(pc, target, esp, type, int_num) VALUES(?, ?, ?, ?, ?)",
		-1, &stmtCall, nullptr);
	if (rc != SQLITE_OK) return false;

	rc = sqlite3_prepare_v2(db,
		"INSERT INTO ret(pc, return_to, esp, type) VALUES(?, ?, ?, ?)",
		-1, &stmtRet, nullptr);
	if (rc != SQLITE_OK) return false;

	rc = sqlite3_prepare_v2(db,
		"INSERT INTO snapshot(data) VALUES(?)",
		-1, &stmtSnapshot, nullptr);
	if (rc != SQLITE_OK) return false;

	return true;
}

void TraceRecorder::FinalizeStatements()
{
	if (stmtMemWrite) { sqlite3_finalize(stmtMemWrite); stmtMemWrite = nullptr; }
	if (stmtMemRead) { sqlite3_finalize(stmtMemRead); stmtMemRead = nullptr; }
	if (stmtCall) { sqlite3_finalize(stmtCall); stmtCall = nullptr; }
	if (stmtRet) { sqlite3_finalize(stmtRet); stmtRet = nullptr; }
	if (stmtSnapshot) { sqlite3_finalize(stmtSnapshot); stmtSnapshot = nullptr; }
}

void TraceRecorder::CreateIndexes()
{
	const char* indexes[] = {
		"CREATE INDEX IF NOT EXISTS idx_memw_addr ON mem_write(addr)",
		"CREATE INDEX IF NOT EXISTS idx_memw_pc ON mem_write(pc)",
		"CREATE INDEX IF NOT EXISTS idx_memr_addr ON mem_read(addr)",
		"CREATE INDEX IF NOT EXISTS idx_memr_pc ON mem_read(pc)",
		"CREATE INDEX IF NOT EXISTS idx_call_target ON call(target)",
		"CREATE INDEX IF NOT EXISTS idx_call_pc ON call(pc)",
		"CREATE INDEX IF NOT EXISTS idx_ret_return_to ON ret(return_to)",
		nullptr
	};

	for (int i = 0; indexes[i] != nullptr; ++i)
	{
		sqlite3_exec(db, indexes[i], nullptr, nullptr, nullptr);
	}
}

void TraceRecorder::BeginTransaction()
{
	sqlite3_exec(db, "BEGIN TRANSACTION", nullptr, nullptr, nullptr);
}

void TraceRecorder::CommitTransaction()
{
	sqlite3_exec(db, "COMMIT", nullptr, nullptr, nullptr);
	insertsSinceCommit = 0;
}

void TraceRecorder::CheckBatchCommit()
{
	if (insertsSinceCommit >= BATCH_SIZE)
	{
		CommitTransaction();
		BeginTransaction();
	}
}

bool TraceRecorder::AddressInRange(uint32_t addr) const
{
	if (config.memRanges.empty())
	{
		return true;
	}
	for (const auto& range : config.memRanges)
	{
		if (addr >= range.first && addr <= range.second)
		{
			return true;
		}
	}
	return false;
}

bool TraceRecorder::PcInRange(uint32_t pc) const
{
	if (config.pcRanges.empty())
	{
		return true;
	}
	for (const auto& range : config.pcRanges)
	{
		if (pc >= range.first && pc <= range.second)
		{
			return true;
		}
	}
	return false;
}

uint32_t TraceRecorder::PackCSEIP(uint16_t cs, uint32_t eip)
{
	return (static_cast<uint32_t>(cs) << 16) | (eip & 0xFFFF);
}

void TraceRecorder::OnMemWrite(uint32_t pc, uint32_t addr, uint8_t size, uint32_t oldVal, uint32_t newVal)
{
	if (!active || !config.captureMemWrite || !PcInRange(pc) || !AddressInRange(addr))
	{
		return;
	}

	if (config.adaptiveThreshold > 0)
	{
		uint64_t addrKey = (static_cast<uint64_t>(addr) << 8) | size;
		auto& tracker = adaptiveWriteTrackers[addrKey];

		if (tracker.saturated)
		{
			if (!tracker.pcsSeen.insert(pc).second)
			{
				return;  // Already seen this PC for saturated address
			}
		}
		else
		{
			if (!tracker.valuesSeen.insert(newVal).second)
			{
				return;  // Already seen this value before saturation
			}
			if (tracker.valuesSeen.size() >= config.adaptiveThreshold)
			{
				tracker.saturated = true;
				tracker.valuesSeen.clear();
				tracker.pcsSeen.insert(pc);
			}
		}
	}
	else
	{
		uint64_t key = (static_cast<uint64_t>(pc) << 32) | addr;

		if (config.deduplicateAllTime)
		{
			if (!seenWriteVals[key].insert(newVal).second)
			{
				return;  // Already seen this (pc, addr, val) combination
			}
		}

		if (config.maxPerLocation > 0 && writeCount[key]++ >= config.maxPerLocation)
		{
			return;
		}
	}

	if (eventQueue.size_approx() >= MAX_QUEUE_SIZE)
	{
		++droppedEvents;
		return;
	}

	TraceEvent evt;
	evt.type = EVT_MEM_WRITE;
	evt.size = size;
	evt.intNum = 0;
	evt.pc = pc;
	evt.addr = addr;
	evt.val = newVal;
	evt.oldVal = oldVal;
	eventQueue.enqueue(evt);
}

void TraceRecorder::OnMemRead(uint32_t pc, uint32_t addr, uint8_t size, uint32_t val)
{
	if (!active || !config.captureMemRead || !PcInRange(pc) || !AddressInRange(addr))
	{
		return;
	}

	if (config.adaptiveThreshold > 0)
	{
		uint64_t addrKey = (static_cast<uint64_t>(addr) << 8) | size;
		auto& tracker = adaptiveReadTrackers[addrKey];

		if (tracker.saturated)
		{
			if (!tracker.pcsSeen.insert(pc).second)
			{
				return;  // Already seen this PC for saturated address
			}
		}
		else
		{
			if (!tracker.valuesSeen.insert(val).second)
			{
				return;  // Already seen this value before saturation
			}
			if (tracker.valuesSeen.size() >= config.adaptiveThreshold)
			{
				tracker.saturated = true;
				tracker.valuesSeen.clear();
				tracker.pcsSeen.insert(pc);
			}
		}
	}
	else
	{
		uint64_t key = (static_cast<uint64_t>(pc) << 32) | addr;

		if (config.deduplicateAllTime)
		{
			if (!seenReadVals[key].insert(val).second)
			{
				return;  // Already seen this (pc, addr, val) combination
			}
		}

		if (config.maxPerLocation > 0 && readCount[key]++ >= config.maxPerLocation)
		{
			return;
		}
	}

	if (eventQueue.size_approx() >= MAX_QUEUE_SIZE)
	{
		++droppedEvents;
		return;
	}

	TraceEvent evt;
	evt.type = EVT_MEM_READ;
	evt.size = size;
	evt.intNum = 0;
	evt.pc = pc;
	evt.addr = addr;
	evt.val = val;
	evt.oldVal = 0;
	eventQueue.enqueue(evt);
}

void TraceRecorder::OnCall(uint32_t pc, uint32_t target, uint32_t esp, CallType type, uint8_t intNum)
{
	if (!active || !config.captureCall)
	{
		return;
	}

	if (config.deduplicateAllTime)
	{
		uint64_t key = (static_cast<uint64_t>(pc) << 32) | target;
		if (!seenCalls.insert(key).second)
		{
			return;
		}
	}

	if (eventQueue.size_approx() >= MAX_QUEUE_SIZE)
	{
		++droppedEvents;
		return;
	}

	TraceEvent evt;
	evt.type = EVT_CALL;
	evt.size = static_cast<uint8_t>(type);
	evt.intNum = intNum;
	evt.pc = pc;
	evt.addr = target;
	evt.val = esp;
	evt.oldVal = 0;
	eventQueue.enqueue(evt);
}

void TraceRecorder::OnRet(uint32_t pc, uint32_t returnTo, uint32_t esp, RetType type)
{
	if (!active || !config.captureRet)
	{
		return;
	}

	if (config.deduplicateAllTime)
	{
		uint64_t key = (static_cast<uint64_t>(pc) << 32) | returnTo;
		if (!seenRets.insert(key).second)
		{
			return;
		}
	}

	if (eventQueue.size_approx() >= MAX_QUEUE_SIZE)
	{
		++droppedEvents;
		return;
	}

	TraceEvent evt;
	evt.type = EVT_RET;
	evt.size = static_cast<uint8_t>(type);
	evt.intNum = 0;
	evt.pc = pc;
	evt.addr = returnTo;
	evt.val = esp;
	evt.oldVal = 0;
	eventQueue.enqueue(evt);
}

void TraceRecorder::OnInstruction()
{
	if (!active)
	{
		return;
	}

	++totalInstructions;
	++instructionsSinceSnapshot;

	if (config.snapshotInterval > 0 && instructionsSinceSnapshot >= config.snapshotInterval)
	{
		needsSnapshot = true;
	}
}

void TraceRecorder::TakeSnapshot(const std::vector<uint8_t>& stateData)
{
	if (!active || stateData.empty())
	{
		return;
	}

	while (snapshotReady.load())
	{
		std::this_thread::yield();
	}

	pendingSnapshot = stateData;
	snapshotReady.store(true);

	instructionsSinceSnapshot = 0;
	needsSnapshot = false;
}

void TraceRecorder::WriterThreadFunc()
{
	TraceEvent evt;
	while (!writerStop.load())
	{
		if (snapshotReady.load())
		{
			sqlite3_bind_blob(stmtSnapshot, 1, pendingSnapshot.data(),
				static_cast<int>(pendingSnapshot.size()), SQLITE_TRANSIENT);
			sqlite3_step(stmtSnapshot);
			sqlite3_reset(stmtSnapshot);
			pendingSnapshot.clear();
			snapshotReady.store(false);
			++insertsSinceCommit;
			CheckBatchCommit();
		}

		if (eventQueue.wait_dequeue_timed(evt, std::chrono::milliseconds(10)))
		{
			if (!ProcessEvent(evt))
			{
				break;  // Database error, stop processing
			}
		}
	}
	if (snapshotReady.load())
	{
		sqlite3_bind_blob(stmtSnapshot, 1, pendingSnapshot.data(),
			static_cast<int>(pendingSnapshot.size()), SQLITE_TRANSIENT);
		sqlite3_step(stmtSnapshot);
		sqlite3_reset(stmtSnapshot);
		pendingSnapshot.clear();
		snapshotReady.store(false);
		++insertsSinceCommit;
		CheckBatchCommit();
	}

	while (eventQueue.try_dequeue(evt))
	{
		ProcessEvent(evt);
	}
}

bool TraceRecorder::ProcessEvent(const TraceEvent& evt)
{
	int rc = SQLITE_OK;

	switch (evt.type)
	{
	case EVT_MEM_WRITE:
		sqlite3_bind_int64(stmtMemWrite, 1, evt.pc);
		sqlite3_bind_int64(stmtMemWrite, 2, evt.addr);
		sqlite3_bind_int(stmtMemWrite, 3, evt.size);
		sqlite3_bind_int64(stmtMemWrite, 4, evt.oldVal);
		sqlite3_bind_int64(stmtMemWrite, 5, evt.val);
		rc = sqlite3_step(stmtMemWrite);
		sqlite3_reset(stmtMemWrite);
		++memWriteCount;
		break;

	case EVT_MEM_READ:
		sqlite3_bind_int64(stmtMemRead, 1, evt.pc);
		sqlite3_bind_int64(stmtMemRead, 2, evt.addr);
		sqlite3_bind_int(stmtMemRead, 3, evt.size);
		sqlite3_bind_int64(stmtMemRead, 4, evt.val);
		rc = sqlite3_step(stmtMemRead);
		sqlite3_reset(stmtMemRead);
		++memReadCount;
		break;

	case EVT_CALL:
		sqlite3_bind_int64(stmtCall, 1, evt.pc);
		sqlite3_bind_int64(stmtCall, 2, evt.addr);
		sqlite3_bind_int64(stmtCall, 3, evt.val);
		sqlite3_bind_int(stmtCall, 4, evt.size);
		sqlite3_bind_int(stmtCall, 5, evt.intNum);
		rc = sqlite3_step(stmtCall);
		sqlite3_reset(stmtCall);
		++callCount;
		break;

	case EVT_RET:
		sqlite3_bind_int64(stmtRet, 1, evt.pc);
		sqlite3_bind_int64(stmtRet, 2, evt.addr);
		sqlite3_bind_int64(stmtRet, 3, evt.val);
		sqlite3_bind_int(stmtRet, 4, evt.size);
		rc = sqlite3_step(stmtRet);
		sqlite3_reset(stmtRet);
		++retCount;
		break;
	}

	if (rc != SQLITE_DONE && rc != SQLITE_OK)
	{
		++dbErrors;
		return false;
	}

	++insertsSinceCommit;
	CheckBatchCommit();
	return true;
}

uint64_t TraceRecorder::GetEventCount() const
{
	return memWriteCount + memReadCount + callCount + retCount;
}
