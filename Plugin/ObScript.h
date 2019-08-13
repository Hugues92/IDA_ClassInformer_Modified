

// Generic version of ObScript structures (based on F4SE definitions).

typedef unsigned __int8  UInt8;
typedef unsigned __int16 UInt16;
typedef unsigned __int32 UInt32;
typedef unsigned __int64 UInt64;

// 0C
struct ObScriptParam
{
	const char	* typeStr;	// 00
	UInt32		typeID;		// 04
	UInt32		isOptional;	// 08
};

class TESObjectREFR;
class Script;
class ScriptLocals;
class ScriptLineBuffer;
class ScriptBuffer;
#define COMMAND_ARGS		ObScriptParam * paramInfo, void * scriptData, TESObjectREFR * thisObj, TESObjectREFR * containingObj, Script * scriptObj, ScriptLocals * locals, double * result, UInt32 * opcodeOffsetPtr
#define COMMAND_ARGS_EVAL	TESObjectREFR * thisObj, void * arg1, void * arg2, double * result

typedef bool(*ObScript_Eval)(COMMAND_ARGS_EVAL);
typedef bool(*ObScript_Execute)(COMMAND_ARGS);
typedef bool(*ObScript_Parse)(UInt32 numParams, ObScriptParam * paramInfo, ScriptLineBuffer * lineBuf, ScriptBuffer * scriptBuf);
typedef bool(*_ExtractArgs)(ObScriptParam * paramInfo, void * scriptData, UInt32 * opcodeOffsetPtr, TESObjectREFR * arg3, TESObjectREFR * thisObj, Script * script, ScriptLocals * eventList, ...);

// 50
struct ObScriptCommand64
{
	const char			* longName;		// 00
	const char			* shortName;	// 08
	UInt32				opcode;			// 10
	UInt32				pad14;			// 14
	const char			* helpText;		// 18
	UInt8				needsParent;	// 20
	UInt8				pad21;			// 21
	UInt16				numParams;		// 22
	UInt32				pad24;			// 24
	ObScriptParam		* params;		// 28

	// handlers
	ObScript_Execute	execute;		// 30
	ObScript_Parse		parse;			// 38
	ObScript_Eval		eval;			// 40

	UInt32				flags;			// 48
	UInt32				pad4C;			// 4C
};

struct ObScriptCommand32
{
	const char			* longName;		// 00
	const char			* shortName;	// 04
	UInt32				opcode;			// 08
	const char			* helpText;		// 0C
	UInt8				needsParent;	// 10
	UInt8				pad21;			// 11
	UInt16				numParams;		// 12
	ObScriptParam		* params;		// 14

	// handlers
	ObScript_Execute	execute;		// 18
	ObScript_Parse		parse;			// 1C
	ObScript_Eval		eval;			// 20

	UInt32				flags;			// 24
};

bool Cmd_Default_Execute(COMMAND_ARGS);
bool Cmd_Default_Eval(COMMAND_ARGS);
bool Cmd_Default_Parse(COMMAND_ARGS);

enum ObScript_Game
{
	kObScriptGmaeID_TES3 = 0x00,
	kObScriptGmaeID_TES4,
	kObScriptGmaeID_FO3,
	kObScriptGmaeID_FNV,
	kObScriptGmaeID_TES5,
	kObScriptGmaeID_TES5se,
	kObScriptGmaeID_FO4,
	kObScriptGmaeID_FO76,
	kObScriptGmaeID_max,
};

enum ObScript_Binary
{
	kObScriptBinary_Runtime = 0x00,
	kObScriptBinary_Editor,
	kObScriptBinary_Launcher,
};

enum ObScript_Size
{
	kObScriptSize32 = 0x00,
	kObScriptSize64,
};

enum ObScript_FO4
{
	kObScript_NumObScriptCommands_FO4 = 0x0332,
	kObScript_NumConsoleCommands_FO4 = 0x0209,

	kObScript_ScriptOpBase_FO4 = 0x1000,
	kObScript_ConsoleOpBase_FO4 = 0x0100,
};

extern ObScript_Game g_gameID;
extern ObScript_Binary g_binary;

extern char g_FirstScriptCommandName[];
extern char g_FirstConsoleCommandName[];
extern __int32 g_ScriptCommandCount;
extern __int32 g_ConsoleCommandCount;

extern ea_t g_firstScriptCommand;
extern ea_t g_firstConsoleCommand;

bool getBSData(LPCSTR Database, FILE* f);
