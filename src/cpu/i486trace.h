#ifndef I486TRACE_IS_INCLUDED
#define I486TRACE_IS_INCLUDED
/* { */

#include <cstdint>
#include <string>
#include <vector>
#include <utility>
#include <unordered_map>
#include <unordered_set>
#include <thread>
#include <atomic>
#include "../externals/readerwriterqueue/readerwriterqueue.h"

struct sqlite3;
struct sqlite3_stmt;

class TraceRecorder
{
public:
	enum CallType : uint8_t
	{
		CALL_NEAR = 0,
		CALL_FAR = 1,
		CALL_INDIRECT_NEAR = 2,
		CALL_INDIRECT_FAR = 3,
		CALL_INT = 4,
	};

	enum RetType : uint8_t
	{
		RET_NEAR = 0,
		RET_FAR = 1,
		RET_IRET = 2,
	};

	enum EventType : uint8_t
	{
		EVT_MEM_READ,
		EVT_MEM_WRITE,
		EVT_CALL,
		EVT_RET,
	};

	struct TraceEvent
	{
		EventType type;
		uint8_t size;      // for mem ops, or CallType/RetType
		uint8_t intNum;    // for CALL_INT
		uint8_t padding;
		uint32_t pc;
		uint32_t addr;     // or target/returnTo
		uint32_t val;      // or esp
		uint32_t oldVal;   // for writes
	};

	struct Config
	{
		bool captureMemRead = true;
		bool captureMemWrite = true;
		bool captureCall = true;
		bool captureRet = true;
		bool deduplicateAllTime = true;  // Skip if (pc, addr, val) ever recorded
		uint32_t maxPerLocation = 1000;  // Max events per (pc, addr) pair, 0 = unlimited
		uint32_t adaptiveThreshold = 0;  // 0 = disabled; N = cap hot addresses after N unique values
		uint64_t snapshotInterval = 10000000;  // instructions between snapshots

		// Optional filters (empty = capture all)
		std::vector<std::pair<uint32_t, uint32_t>> memRanges;  // {start, end} pairs for memory addresses
		std::vector<std::pair<uint32_t, uint32_t>> pcRanges;   // {start, end} pairs for PC (code location)
	};

	TraceRecorder();
	~TraceRecorder();

	bool Start(const std::string& dbPath, const Config& config);
	void Stop();
	bool IsActive() const;

	void OnMemWrite(uint32_t pc, uint32_t addr, uint8_t size, uint32_t oldVal, uint32_t newVal);
	void OnMemRead(uint32_t pc, uint32_t addr, uint8_t size, uint32_t val);
	void OnCall(uint32_t pc, uint32_t target, uint32_t esp, CallType type, uint8_t intNum = 0);
	void OnRet(uint32_t pc, uint32_t returnTo, uint32_t esp, RetType type);
	void OnInstruction();

	void TakeSnapshot(const std::vector<uint8_t>& stateData);

	uint64_t GetEventCount() const;
	uint64_t GetSeq() const { return seq; }
	uint64_t GetInstructionCount() const { return totalInstructions; }
	uint64_t GetDroppedEvents() const { return droppedEvents; }
	uint64_t GetDbErrors() const { return dbErrors; }
	bool NeedsSnapshot() const { return needsSnapshot; }

	const Config& GetConfig() const { return config; }

	static uint32_t PackCSEIP(uint16_t cs, uint32_t eip);

private:
	sqlite3* db = nullptr;
	Config config;
	uint64_t seq = 0;
	uint64_t totalInstructions = 0;
	uint64_t instructionsSinceSnapshot = 0;
	std::atomic<bool> active{false};
	bool needsSnapshot = false;

	sqlite3_stmt* stmtMemWrite = nullptr;
	sqlite3_stmt* stmtMemRead = nullptr;
	sqlite3_stmt* stmtCall = nullptr;
	sqlite3_stmt* stmtRet = nullptr;
	sqlite3_stmt* stmtSnapshot = nullptr;

	uint64_t insertsSinceCommit = 0;
	static constexpr uint64_t BATCH_SIZE = 500000;

	uint64_t memWriteCount = 0;
	uint64_t memReadCount = 0;
	uint64_t callCount = 0;
	uint64_t retCount = 0;
	std::atomic<uint64_t> droppedEvents{0};
	std::atomic<uint64_t> dbErrors{0};

	// Deduplication: (pc << 32 | addr) -> set of recorded values
	std::unordered_map<uint64_t, std::unordered_set<uint32_t>> seenReadVals;
	std::unordered_map<uint64_t, std::unordered_set<uint32_t>> seenWriteVals;
	std::unordered_set<uint64_t> seenCalls;  // (pc << 32 | target)
	std::unordered_set<uint64_t> seenRets;   // (pc << 32 | returnTo)

	// Pending snapshot (processed by writer thread)
	std::vector<uint8_t> pendingSnapshot;
	std::atomic<bool> snapshotReady{false};

	// Rate limiting: (pc << 32 | addr) -> count
	std::unordered_map<uint64_t, uint32_t> readCount;
	std::unordered_map<uint64_t, uint32_t> writeCount;

	// Adaptive threshold tracking: per (addr, size) tracker
	struct AddrTracker
	{
		std::unordered_set<uint32_t> valuesSeen;
		std::unordered_set<uint32_t> pcsSeen;
		bool saturated = false;
	};
	// Key: (addr << 8 | size)
	std::unordered_map<uint64_t, AddrTracker> adaptiveReadTrackers;
	std::unordered_map<uint64_t, AddrTracker> adaptiveWriteTrackers;

	// Async writer thread
	static constexpr size_t MAX_QUEUE_SIZE = 1000000;
	moodycamel::BlockingReaderWriterQueue<TraceEvent> eventQueue;
	std::thread writerThread;
	std::atomic<bool> writerStop{false};
	void WriterThreadFunc();
	bool ProcessEvent(const TraceEvent& evt);

	bool InitDatabase(const std::string& dbPath);
	bool PrepareStatements();
	void FinalizeStatements();
	void CreateIndexes();
	void BeginTransaction();
	void CommitTransaction();
	void CheckBatchCommit();
	bool AddressInRange(uint32_t addr) const;
	bool PcInRange(uint32_t pc) const;
};

/* } */
#endif
