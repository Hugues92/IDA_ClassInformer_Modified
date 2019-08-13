#include "stdafx.h"
#include "RTTI.h"
#include "ObScript.h"
#include <WaitBoxEx.h>
#include <fpro.h>
#include <strlist.hpp>

#define BethDefinitionTxt "BethesdaDefinition.txt"
#define BethDefinitionIni ".\\BethesdaDefinition.ini"
#define NewBethDefinitionIni ".\\NewBethesdaDefinition.ini"

#include <Windows.h>

char g_FirstScriptCommandName[MAXSTR];
char g_FirstConsoleCommandName[MAXSTR];
__int32 g_ScriptCommandCount = 0;
__int32 g_ScriptCommandXref = 0;
__int32 g_ConsoleCommandCount = 0;
__int32 g_ConsoleCommandXref = 0;
__int32 g_ParamTypeCount = 0;
__int32 g_ParamTypeMax = -1;
__int32	g_SettingCollectionCount = 0;
qvector<qstring> g_SettingCollectionVFTnames;

ea_t g_firstScriptCommand;
ea_t g_firstConsoleCommand;

char * GetString(char * result, FILE* f)
{
	char Buffer[MAXSTR]="";
	if (-1<qfscanf(f, "%s\n", Buffer))
	{
		strcpy_s(result, (MAXSTR - 1), Buffer);
		return result;
	}
	else
		return NULL;
};

char * GetString(char * result, char * key, char * section)
{
	char Buffer[MAXSTR] = "";
	if (GetPrivateProfileString(section, key, "", Buffer, MAXSTR - 1, BethDefinitionIni))
	{
		strcpy_s(result, (MAXSTR - 1), Buffer);
		return result;
	}
	else
		return NULL;
};

__int64 GetInt(char * key, char * section)
{
	char Buffer[MAXSTR] = "";
	UINT result = GetPrivateProfileInt(section, key, (UINT)-1, BethDefinitionIni);
	if ((UINT)(-1) == result)
		return -1;
	return result;
};

char * GetString(char* result, ea_t ea)
{
	strcpy_s(result, 1, "");
	char Buffer[MAXSTR];
	size_t l = 0;
	if (BADADDR != ea)
#ifndef __EA64__
		ea = get_dword(ea);
#else
		ea = get_qword(ea);
#endif
	if (BADADDR != ea)
		for (ea_t i = 0; i < MAXSTR; ++i)
			if (!get_byte(ea + i))
				break;
			else
				l++;
	if (l && l < MAXSTR)
	{
		get_bytes(Buffer, ++l, ea);
		strcpy_s(result, l, Buffer);
		return result;
	}
	return NULL;
};

void TruncateTrailingBlanks(LPSTR data)
{
	size_t l = strlen(data);
	while (data && l && (data[l-1] < ' '))
	{
		data[l-1] = 0;
		l = strlen(data);
	}
}

// Create structure definition w/comment
static struc_t *AddStruct(__out tid_t &id, __in LPCSTR name, LPCSTR comment)
{
	struc_t *structPtr = NULL;

	// If it exists get current def else create it
	id = get_struc_id(name);
	if (id == BADADDR)
		id = add_struc(BADADDR, name);
	if (id != BADADDR)
		structPtr = get_struc(id);

	if (structPtr)
	{
		// Clear the old one out if it exists and set the comment
		int dd = del_struc_members(structPtr, 0, MAXADDR);
		dd = dd;
		bool rr = set_struc_cmt(id, comment, true);
		rr = rr;
	}
	else
		msg("** AddStruct(\"%s\") failed!\n", name);

	return(structPtr);
}

static struc_t *AddClassStruct(__inout tid_t &id, __in LPCSTR name)
{
	char cmt[MAXSTR] = "";
	::qsnprintf(cmt, MAXSTR - 1, "Class %s as struct (#classinformer)", name);
	return AddStruct(id, name, cmt);
}

static tid_t s_ObScriptCommand_ID = 10;

#ifndef __EA64__
typedef ObScriptCommand32 ObScriptCommand;
#else
typedef ObScriptCommand64 ObScriptCommand;
#endif

void addDefinitionsToIda()
{
	// Member type info for 32bit offset types
	opinfo_t mtoff;
	ZeroMemory(&mtoff, sizeof(refinfo_t));
#ifndef __EA64__
	mtoff.ri.flags = REF_OFF32;
#define EAOFFSET (off_flag() | dword_flag())
	typedef ObScriptCommand32 ObScriptCommand;
#else
	mtoff.ri.flags = REF_OFF64;
#define EAOFFSET (off_flag() | qword_flag())
	typedef ObScriptCommand64 ObScriptCommand;
#endif
	mtoff.ri.target = BADADDR;

	// Add structure member
#define ADD_MEMBER(_flags, _mtoff, TYPE, _member)\
	    {\
	    TYPE _type;\
        (void)_type;\
	    if(add_struc_member(structPtr, #_member, (ea_t)offsetof(TYPE, _member), (_flags), _mtoff, (asize_t)sizeof(_type._member)) != 0)\
		    msg(" ** ADD_MEMBER(): %s failed! %d, %d **\n", #_member, offsetof(TYPE, _member), sizeof(_type._member));\
	    }

	struc_t *structPtr;
	if (structPtr = AddStruct(s_ObScriptCommand_ID, "ObScriptCommand", "BETH ObScriptCommand struct (#classinformer)"))
	{
		ADD_MEMBER(EAOFFSET, &mtoff, ObScriptCommand, longName);
		ADD_MEMBER(EAOFFSET, &mtoff, ObScriptCommand, shortName);
		ADD_MEMBER(dword_flag(), NULL, ObScriptCommand, opcode);
#ifdef __EA64__
		ADD_MEMBER(dword_flag(), NULL, ObScriptCommand, pad14);
#endif
		ADD_MEMBER(EAOFFSET, &mtoff, ObScriptCommand, helpText);
		ADD_MEMBER(byte_flag(), NULL, ObScriptCommand, needsParent);
		ADD_MEMBER(byte_flag(), NULL, ObScriptCommand, pad21);
		ADD_MEMBER(word_flag(), NULL, ObScriptCommand, numParams);
#ifdef __EA64__
		ADD_MEMBER(dword_flag(), NULL, ObScriptCommand, pad21);
#endif
		ADD_MEMBER(EAOFFSET, &mtoff, ObScriptCommand, params);
		ADD_MEMBER(EAOFFSET, &mtoff, ObScriptCommand, execute);
		ADD_MEMBER(EAOFFSET, &mtoff, ObScriptCommand, parse);
		ADD_MEMBER(EAOFFSET, &mtoff, ObScriptCommand, eval);
		ADD_MEMBER(dword_flag(), NULL, ObScriptCommand, flags);
#ifdef __EA64__
		ADD_MEMBER(dword_flag(), NULL, ObScriptCommand, pad4C);
#endif

	}

#undef ADD_MEMBER
}

struct ObScriptParamInternal
{
	__int32 typeID;
	qstring	name;
	__int16	wbType;
	qstring	firstName;
	__int32 used;
};

static std::vector<ObScriptParamInternal> knownTypeID;
#define InvalidTypeID -1

bool AppendToKnownTypes(size_t typeID, ObScriptParamInternal* newP = NULL, bool import=false)
{
	// msgR("\t\t\t\t\t\t>typeID=% 3d size=% 3d\n", typeID, knownTypeID.size());
	char id[MAXSTR] = "";
	_itoa((__int32)typeID, id, 10);

	ObScriptParamInternal p;
	p.name = "";
	p.typeID = InvalidTypeID;
	p.wbType = InvalidTypeID;
	p.firstName = "";
	p.used = 0;
	for (size_t i = knownTypeID.size(); i <= typeID; ++i)
		knownTypeID.push_back(p);
	// msgR("\t\t\t\t\t\t<typeID=% 3d size=% 3d\n", typeID, knownTypeID.size());

	p = knownTypeID[typeID];
	if (p.typeID == InvalidTypeID)
		if (!newP)
		{
			p.name = id;
			p.typeID = (__int32)typeID;
		}
		else
		{
			p = *newP;
			if (p.name.empty())
			{
				p.name = id;
			}
		}
	if (newP)
	{
		if (p.firstName.empty() && !newP->firstName.empty())
			p.firstName = newP->firstName;
		if (p.name.empty() && !newP->name.empty())
			p.name = newP->name;
	}
	if (!import)
		p.used += 1;
	knownTypeID[typeID] = p;
	return TRUE;
};

char * CountToString(__int8 count)
{
	switch (count)
	{
	case 1: return "One";
	case 2: return "Two";
	case 3: return "Three";
	case 4: return "Four";
	case 5: return "Five";
	case 6: return "Six";
	case 7: return "Seven";
	case 8: return "Eight";
	case 9: return "Nine";
	case 10: return "Ten";
	default:
		return "BadCount";
	}
};

char * AppendParam(char * Buffer, size_t count, size_t typeID, bool optional)
{
	char intBuff[MAXSTR];
	strcat_s(Buffer, (MAXSTR - 1), CountToString((__int8)count));
	if (optional) strcat_s(Buffer, (MAXSTR - 1), "Optional");
	bool done = false;
	if (knownTypeID.size() > typeID)
	{
		ObScriptParamInternal p = knownTypeID[typeID];
		if (!p.name.empty())
		{
			strcat_s(Buffer, (MAXSTR - 1), p.name.c_str());
			done = true;
		}
	}
	if (!done)
		strcat_s(Buffer, (MAXSTR - 1), _itoa((__int32)typeID, intBuff, 10));	// We need a decoding table and a re encoding table to (none, int, formID)
	strcat_s(Buffer, (MAXSTR - 1), "_");
	return Buffer;
};

// Get address/pointer value
inline ea_t getEa(ea_t ea)
{
#ifndef __EA64__
	return((ea_t)get_32bit(ea));
#else
	return((ea_t)get_64bit(ea));
#endif
}

void DoParams(ea_t ea, char * cmdName, __int16 numParams)
{
	//msgR("\t\t\t\t%x /%s/ %d\n", ea, cmdName, numParams);
	if (BADADDR != ea)
	{
		ea_t cmd = getEa(ea);
		if (cmd != BADADDR && cmd && numParams > 0)
		{
			flags_t f = get_flags(cmd);
			if (!has_name(f))
			{
				__int32	count = 0;
				__int32	last = InvalidTypeID;
				bool lastOpt = false;
				char Buffer[MAXSTR] = "__ICI__kParams_";
				char intBuff[32];
				// strcat_s(Buffer, (MAXSTR - 1), _itoa(numParams, intBuff, 10));
				// strcat_s(Buffer, (MAXSTR - 1), "_");
				ea_t eat = cmd;
				for (__int32 i = 0; i < numParams; ++i)
				{
					ea_t start = eat;
					ea_t pName = getEa(eat);
					char c[MAXSTR] = "";
					GetString(c, eat);
					eat += sizeof(ea_t);
					__int32 typeID = get_32bit(eat);
					eat += sizeof(__int32);
					bool optional = get_32bit(eat) == 0 ? false : true;
					eat += sizeof(__int32);
					if (last == typeID && lastOpt == optional)
						if (count < 10)
							count += 1;
						else
						{
							AppendParam(Buffer, count, last, lastOpt);
							count = 0;
							last = InvalidTypeID;
							lastOpt = false;
						}
					else
					{
						if (count)
							AppendParam(Buffer, count, last, lastOpt);
						count = 1;
						last = typeID;
						lastOpt = optional;
						if (strlen(c))
						{
							ObScriptParamInternal * p = new ObScriptParamInternal;
							p->typeID = typeID;
							p->name = "";
							p->wbType = InvalidTypeID;
							p->firstName = c;
							AppendToKnownTypes(typeID, p);
							delete p;
						}
						else
							AppendToKnownTypes(typeID);
					}
				}
				if (count)
				{
					AppendParam(Buffer, count, last, lastOpt);
					//msgR("\t\t\t\t\t%x /%s/ /%x/ %d of %d / %d : %x / %d : %x /%s/\n", start, cmdName, pName, i + 1, numParams, typeID, typeID, optional, optional, Buffer);
				}
				strcat_s(Buffer, (MAXSTR - 1), _itoa(cmd, intBuff, 16));
				set_name(cmd, Buffer);
				//msgR("\t\t\t\t\t%x /%s/  %d /%s/\n", cmd, cmdName, numParams, Buffer);
			}
		};
	}
};

void DoCmd(ea_t ea, char * cmdName, char * subName)
{
	if (BADADDR != ea)
	{
		ea_t cmd = getEa(ea);
		if (cmd != BADADDR && cmd)
		{
			flags_t f = get_flags(cmd);
			if (has_name(f))
			{
				qstring cname;
				get_ea_name(&cname, cmd);
				if (strstr(cname.c_str(), "unknown_libname"))
					set_name(cmd, "");
				f = get_flags(cmd);
			}
			if (!has_name(f))
			{
				char Buffer[MAXSTR] = "Cmd_";
				strcat_s(Buffer, (MAXSTR - 1), cmdName);
				strcat_s(Buffer, (MAXSTR - 1), "_");
				strcat_s(Buffer, (MAXSTR - 1), subName);
				set_name(cmd, Buffer);
			}
		}
	}
};

size_t unusedCommand = 0;

void LoopCmdTable(ea_t start, size_t count, char * table)
{
	char cmdComment[MAXSTR] = "";
	char cmdName[MAXSTR] = "";
#ifdef __EA64__
	size_t soo = 0x050;
#else
	size_t soo = sizeof(ObScriptCommand);
#endif
	ea_t ea = start;
	ea_t eaEnd = start + (ea_t)(soo*count);
	::qsnprintf(cmdComment, (size_t)(MAXSTR - 1), "Bethesda Command table for %s of size %d [" EAFORMAT ":" EAFORMAT "]", table, count, start, eaEnd);
	add_extra_cmt(start, true, cmdComment);
	msgR("\t\t%35s %s Cmd:\tfrom %x to %x (%d)\n", "Looping table:", table, start, start + count * soo, soo);
	for (size_t i = 0; i < min(count, 20000); i++)
	{
			if (0 == i % 100)
				msgR("\t\t%35s %s Cmd:\t% 7d of % 7d\n", "Looping table:", table, i + 1, count);
			GetString(cmdName, ea);
			TruncateTrailingBlanks(cmdName);
			if (!strlen(cmdName) && strstr(cmdName, " "))
				::qsnprintf(cmdName, (MAXSTR - 1), "Unused_%d", unusedCommand++);
			if (strlen(cmdName) && 0 == strstr(cmdName, " "))
			{
				ea_t eat = sizeof(ObScriptCommand);
				char name[MAXSTR];
				strcpy(name, "__ICI__CommandInfo__");
				strcat_s(name, (MAXSTR - 1), cmdName);
				for (eat = ea; eat < ea + sizeof(ObScriptCommand); ++eat)
					del_items(eat, 0);
				if (!has_name(get_flags(ea)))
					set_name(ea, name);
				bool ds = false; //  doStruct(ea, sizeof(ObScriptCommand), s_ObScriptCommand_ID);
				eat = ea;
#ifdef __EA64__
				if (!ds) create_qword(eat, sizeof(ea_t));		// 00
				eat += sizeof(ea_t);
				if (!ds) create_qword(eat, sizeof(ea_t));		// 08
				eat += sizeof(ea_t);
#else
				if (!ds) create_dword(eat, sizeof(ea_t));		// 00
				eat += sizeof(ea_t);
				if (!ds) create_dword(eat, sizeof(ea_t));		// 04
				eat += sizeof(ea_t);
#endif
				if (!ds) create_dword(eat, sizeof(__int32));	// 08 - 10
				eat += sizeof(__int32);
#ifdef __EA64__
				if (!ds) create_dword(eat, sizeof(__int32));	// 14
				eat += sizeof(__int32);
				if (!ds) create_qword(eat, sizeof(ea_t));		// 18
				eat += sizeof(ea_t);
#else
				if (!ds) create_dword(eat, sizeof(__int32));	// 0C
				eat += sizeof(__int32);
#endif
				if (!ds) create_byte(eat, sizeof(__int8));	// 10 - 20
				eat += sizeof(__int8);
				if (!ds) create_byte(eat, sizeof(__int8));	// 11 - 21
				eat += sizeof(__int8);
				if (!ds) create_word(eat, sizeof(__int16));	// 12 - 22
				__int16 numParams = get_16bit(eat);
				eat += sizeof(__int16);
#ifdef __EA64__
				if (!ds) create_dword(eat, sizeof(__int32));	// 24
				eat += sizeof(__int32);
#endif
#ifdef __EA64__
				if (!ds) create_qword(eat, sizeof(ea_t));	// 28	* Params	
				DoParams(eat, cmdName, numParams);
				eat += sizeof(ea_t);
				if (!ds) create_qword(eat, sizeof(ea_t));	// 30	* Exec	
				DoCmd(eat, cmdName, "Execute");
				eat += sizeof(ea_t);
				if (!ds) create_qword(eat, sizeof(ea_t));	// 38	* Parse
				DoCmd(eat, cmdName, "Parse");
				eat += sizeof(ea_t);
				if (!ds) create_qword(eat, sizeof(ea_t));	// 40	* Eval
				DoCmd(eat, cmdName, "Eval");
				eat += sizeof(ea_t);
#else
				if (!ds) create_dword(eat, sizeof(ea_t));	// 14	* Params	
				DoParams(eat, cmdName, numParams);
				eat += sizeof(ea_t);
				if (!ds) create_dword(eat, sizeof(ea_t));	// 18	* Exec
				DoCmd(eat, cmdName, "Execute");
				eat += sizeof(ea_t);
				if (!ds) create_dword(eat, sizeof(ea_t));	// 1C	* Parse
				DoCmd(eat, cmdName, "Parse");
				eat += sizeof(ea_t);
				if (!ds) create_dword(eat, sizeof(ea_t));	// 20	* Eval
				DoCmd(eat, cmdName, "Eval");
				eat += sizeof(ea_t);
#endif
				if (!ds) create_dword(eat, sizeof(__int32));	// 24 - 48
				eat += sizeof(__int32);
#ifdef __EA64__
				if (!ds) create_dword(eat, sizeof(__int32));	// 4C
				eat += sizeof(__int32);
#endif
			}	// 28 - 50
			ea += (ea_t)soo;
	}
};

// Gather Bethesda Software data
bool getBSData(LPCSTR Database, FILE* f)
{
#ifndef __DEBUG
	try
#endif
	{
		BOOL foundData = false;
		BOOL foundNewData = false;
		if (0 < GetInt("Version", "General"))
		{
			foundNewData = true;
			GetString(g_FirstScriptCommandName, "firstName", "ScriptCommands");
			if (g_FirstScriptCommandName)
				if (g_ScriptCommandXref=GetInt("nameXRef", "ScriptCommands"))
					if ((UINT)-1 != (g_ScriptCommandCount = GetInt("Count", "ScriptCommands")))
						GetString(g_FirstConsoleCommandName, "firstName", "ConsoleCommands");
			if (g_FirstConsoleCommandName)
				if (g_ConsoleCommandXref = GetInt("nameXRef", "ConsoleCommands"))
					if ((UINT)-1 != (g_ConsoleCommandCount = GetInt("Count", "ConsoleCommands")))
						foundData = true;
			if (foundData)
			{
				g_ParamTypeCount=GetInt("Count", "ParamTypes");
				g_ParamTypeMax = GetInt("Max", "ParamTypes");
				msgR("\t\t%3d found for %d Max\n", g_ParamTypeCount, g_ParamTypeMax);
				if (g_ParamTypeCount)
				{
					__int32 typeID;
					__int16 wbType;
					int n = 0;
					char buffer[MAXSTR];
					char a[16];
					for (__int32 i = 0; i <= g_ParamTypeMax; ++i)
					{
						GetString(buffer, _itoa(i, a, 10), "ParamTypeNames");
						__int32 t = GetInt(_itoa(i, a, 10), "ParamTypeWBTypes");
						if (strlen(buffer) && (-1<t))
						{
							ObScriptParamInternal op;
							op.firstName = "";
							typeID = i;
							op.typeID = typeID;
							op.name = buffer;
							wbType = t;
							op.wbType = wbType;
							op.used = 0;
							AppendToKnownTypes(typeID, &op, true);
							//msgR("\t\t\t%3d of %3d : %4d '%s' %d\n", i, g_ParamTypeMax, typeID, op.name, wbType);
						}
						else
						{
							//msgR("\t\t\t\tNo data.\n", n);
							//foundData = false;
							//break;
						}
					}
				}
			}
			if (foundData)
			{
				char strCHANGE_FORM_FLAGS[MAXSTR];
				if (GetString(strCHANGE_FORM_FLAGS, "ChangeFormFlag", "xEditPlugin"))
				{
					msgR("\t\t%s found\n", strCHANGE_FORM_FLAGS);
					ea_t ea = get_name_ea(BADADDR, strCHANGE_FORM_FLAGS);
					if (BADADDR != ea)
					{
						msg("\t\tFound '%s' at %x\n", strCHANGE_FORM_FLAGS, ea);
						xrefblk_t xb;
						ea_t doShowChangeFlagsName = BADADDR;
						if (xb.first_to(ea, XREF_ALL))
						{
							doShowChangeFlagsName = xb.from;
						}
						if (BADADDR != doShowChangeFlagsName)
						{
#define doShowChangeFlagsNameName "doShowChangeFlagsName"
							msgR("\t\tFound xref to '%s' at " EAFORMAT "\n", strCHANGE_FORM_FLAGS, doShowChangeFlagsName);
#undef doShowChangeFlagsNameName 
						}
					}
#define s_changeFormTypeArrayBytes "40 00 00 00 41 00 00 00 42 00 00 00 44 00 00 00"	// That's for Fallout 4, should be in BethesdaDefinitions
					// F4: Search for class `anonymous namespace'::ObsoleteSaveCallback `RTTI Type Descriptor'
					// Then convert from a@ to table of 50 DWords.
					// GetString(s_changeFormTypeArrayBytes, f);
#undef s_changeFormTypeArrayBytes 
				}
			}
			if (foundData)
			{
				if ((UINT)-1!=(g_SettingCollectionCount=GetInt("Count", "Settings")))
					for (__int32 i = 0; i < g_SettingCollectionCount; ++i)
					{
						char tempStr[MAXSTR] = "";
						char a[16];
						GetString(tempStr, _itoa(i, a, 10), "SettingNames");
						g_SettingCollectionVFTnames.push_back(qstring(tempStr));
					}
			}
		}
		if (!foundNewData)
		{
			FILE* f = NULL;
			if (f = qfopen(BethDefinitionTxt, "r"))
			{
				GetString(g_FirstScriptCommandName, f);
				if (g_FirstScriptCommandName)
					if (qfscanf(f, "%d\n", &g_ScriptCommandXref))
						if (qfscanf(f, "%d\n", &g_ScriptCommandCount))
							GetString(g_FirstConsoleCommandName, f);
				if (g_FirstConsoleCommandName)
					if (qfscanf(f, "%d\n", &g_ConsoleCommandXref))
						if (qfscanf(f, "%d\n", &g_ConsoleCommandCount))
							foundData = true;
				if (foundData)
				{
					char a[16];
					WritePrivateProfileString("General", "Version", _itoa(1, a, 10), BethDefinitionIni);
					WritePrivateProfileString("ScriptCommands", "firstName", g_FirstScriptCommandName, BethDefinitionIni);
					WritePrivateProfileString("ScriptCommands", "nameXRef", _itoa(g_ScriptCommandXref, a, 10), BethDefinitionIni);
					WritePrivateProfileString("ScriptCommands", "Count", _itoa(g_ScriptCommandCount, a, 10), BethDefinitionIni);
					WritePrivateProfileString("ConsoleCommands", "firstName", g_FirstConsoleCommandName, BethDefinitionIni);
					WritePrivateProfileString("ConsoleCommands", "nameXRef", _itoa(g_ConsoleCommandXref, a, 10), BethDefinitionIni);
					WritePrivateProfileString("ConsoleCommands", "Count", _itoa(g_ConsoleCommandCount, a, 10), BethDefinitionIni);
					qfscanf(f, "%d\n", &g_ParamTypeCount);
					// msgR("\t\t%3d found\n", g_ParamTypeCount);
					if (g_ParamTypeCount)
					{
						WritePrivateProfileString("ParamTypes", "Count", _itoa(g_ParamTypeCount, a, 10), BethDefinitionIni);
						__int32 typeID;
						__int16 wbType;
						int n = 0;
						char buffer[MAXSTR];
						for (__int32 i = 0; i < g_ParamTypeCount; ++i)
						{
							qfgets(buffer, (MAXSTR - 1), f);
							if (strlen(buffer))
							{
								if (buffer[strlen(buffer) - 1] == '\n')
									buffer[strlen(buffer) - 1] = 0;
								//msgR("\t\t\t\t%d: '%s'\n", i, buffer);
								ObScriptParamInternal op;
								op.firstName = "";
								char * p = buffer;
								char * s = strstr(p, ";");
								if (s)
								{
									*s = 0;
									typeID = atoi(p);
									op.typeID = typeID;
									p = s + 1;
								}
								else
								{
									msgR("\t\t\t\t%d: no typeID\n", i);
									break;
								}
								s = strstr(p, ";");
								if (s)
								{
									*s = 0;
									op.name = p;
									p = s + 1;
								}
								else
								{
									msgR("\t\t\t\t%d: no name\n", i);
									break;
								}
								if (p)
								{
									wbType = atoi(p);
									op.wbType = wbType;
									p = s + 1;
								}
								else
								{
									msgR("\t\t\t\t%d: no wbType\n", i);
									break;
								}
								op.used = 0;
								char k[16];
								_itoa(typeID, k, 10);
								WritePrivateProfileString("ParamTypeNames", k, op.name.c_str(), BethDefinitionIni);
								WritePrivateProfileString("ParamTypeWBTypes", k, _itoa(wbType, a, 10), BethDefinitionIni);
								AppendToKnownTypes(typeID, &op, true);
								msgR("\t\t\t%3d of %3d : %4d '%s' %d\n", i + 1, g_ParamTypeCount, typeID, op.firstName, wbType);
							}
							else
							{
								msgR("\t\t\t\tNo data.\n", n);
								foundData = false;
								break;
							}
						}
						WritePrivateProfileString("ParamTypes", "Max", _itoa((__int32)knownTypeID.size()-1, a, 10), BethDefinitionIni);
					}
				}
			}
			if (foundData)
			{
				char strCHANGE_FORM_FLAGS[MAXSTR];
				if (GetString(strCHANGE_FORM_FLAGS, f))
				{
					WritePrivateProfileString(strCHANGE_FORM_FLAGS, "ChangeFormFlag", strCHANGE_FORM_FLAGS, BethDefinitionIni);
					msgR("\t\t%s found\n", strCHANGE_FORM_FLAGS);
					ea_t ea = get_name_ea(BADADDR, strCHANGE_FORM_FLAGS);
					if (BADADDR != ea)
					{
						msg("\t\tFound '%s' at %x\n", strCHANGE_FORM_FLAGS, ea);
						xrefblk_t xb;
						ea_t doShowChangeFlagsName = BADADDR;
						if (xb.first_to(ea, XREF_ALL))
						{
							doShowChangeFlagsName = xb.from;
						}
						if (BADADDR != doShowChangeFlagsName)
						{
#define doShowChangeFlagsNameName "doShowChangeFlagsName"
							msgR("\t\tFound xref to '%s' at " EAFORMAT "\n", strCHANGE_FORM_FLAGS, doShowChangeFlagsName);
						}
					}
#define s_changeFormTypeArrayBytes "40 00 00 00 41 00 00 00 42 00 00 00 44 00 00 00"	// That's for Fallout 4, should be in BethesdaDefinitions
					// F4: Search for class `anonymous namespace'::ObsoleteSaveCallback `RTTI Type Descriptor'
					// Then convert from a@ to table of 50 DWords.
					// GetString(s_changeFormTypeArrayBytes, f);
				}
			}
		}
		if (!foundData)
			return(TRUE);

		msg("\nFound Bethesda game.\n");
		msg("\tFirst Script Command Name is '%s'. %d commands expected\n", g_FirstScriptCommandName, g_ScriptCommandCount);
		msg("\tFirst Console Command Name is '%s'. %d commands expected\n", g_FirstConsoleCommandName, g_ConsoleCommandCount);
		msgR("\t%d param types defined\n", g_ParamTypeCount);

		// addDefinitionsToIda();

		ea_t ea = get_name_ea(BADADDR, g_FirstScriptCommandName);
		if (BADADDR != ea)
		{
			msg("\t\tFound '%s' at %x\n", g_FirstScriptCommandName, ea);
			xrefblk_t xb;
			__int32 r = 0;
			if (xb.first_to(ea, XREF_ALL))
			{
				while (++r < g_ScriptCommandXref){ xb.next_to(); }
				g_firstScriptCommand = xb.from;
			}
			if (BADADDR != g_firstScriptCommand)
			{
				msgR("\t\t\tFound [%x] ref at %x\n", ea, g_firstScriptCommand);
				LoopCmdTable(g_firstScriptCommand, g_ScriptCommandCount, "Script");
			}
		}

		ea = get_name_ea(BADADDR, g_FirstConsoleCommandName);
		if (BADADDR != ea)
		{
			msg("\t\tFound '%s' at %x\n", g_FirstConsoleCommandName, ea);
			xrefblk_t xb;
			__int32 r = 0;
			if (xb.first_to(ea, XREF_ALL))
			{
				while (++r < g_ConsoleCommandXref){ xb.next_to(); }
				g_firstConsoleCommand = xb.from;
			}
			if (BADADDR != g_firstConsoleCommand)
			{
				msg("\t\t\tFound [%x] ref at %x\n", ea, g_firstConsoleCommand);
				LoopCmdTable(g_firstConsoleCommand, g_ConsoleCommandCount, "Console");
			}
		//			UINT s = search(NULL, NULL, NULL, NULL, "FalloutNV.esm", 0);
		}

		if (BADADDR != g_firstScriptCommand)
		{
			qstring s;
			qfprintf(f, "UInt32 WBEncode(ObScriptParam param)\n");
			qfprintf(f, "{\n");
			qfprintf(f, "\tswitch (param.typeID)\n");
			qfprintf(f, "\t{\n");
			for (__int32 i = 0; i < (__int32)knownTypeID.size(); ++i)
			{
				ObScriptParamInternal p = knownTypeID[i];
				if (p.typeID > InvalidTypeID)
				{
					s.sprnt("\t\tcase % 3d:\treturn %4d; \t//\t %02x '%s' (%s) %3d\n", p.typeID, p.wbType, p.typeID, p.name.c_str(), p.firstName.c_str(), 
						p.used > 0 ? p.used : 0);
					qfprintf(f, s.c_str());
				}
			}
			qfprintf(f, "\t\tdefault:\treturn 0;\n");
			qfprintf(f, "\t}\n");
			qfprintf(f, "};\n\n\n\n");

			qfprintf(f, "enum ParamType\n");
			qfprintf(f, "{\n");
			for (__int32 i = 0; i < (__int32)knownTypeID.size(); ++i)
			{
				ObScriptParamInternal p = knownTypeID[i];
				if (p.typeID > InvalidTypeID)
				{
					s.sprnt("\tkParamType_%s =\t\t\t0x%02x,\t // %3d %3d (%s) %3d\n", p.name.c_str(), p.typeID, p.typeID, p.wbType, p.firstName.c_str(), 
						p.used > 0 ? p.used : 0);
					qfprintf(f, s.c_str());
				}
			}
			qfprintf(f, "};\n\n\n\n");


			char a[16];
			WritePrivateProfileString("General", "Version", _itoa(1, a, 10), NewBethDefinitionIni);
			WritePrivateProfileString("ScriptCommands", "firstName", g_FirstScriptCommandName, NewBethDefinitionIni);
			WritePrivateProfileString("ScriptCommands", "nameXRef", _itoa(g_ScriptCommandXref, a, 10), NewBethDefinitionIni);
			WritePrivateProfileString("ScriptCommands", "Count", _itoa(g_ScriptCommandCount, a, 10), NewBethDefinitionIni);
			WritePrivateProfileString("ConsoleCommands", "firstName", g_FirstConsoleCommandName, NewBethDefinitionIni);
			WritePrivateProfileString("ConsoleCommands", "nameXRef", _itoa(g_ConsoleCommandXref, a, 10), NewBethDefinitionIni);
			WritePrivateProfileString("ConsoleCommands", "Count", _itoa(g_ConsoleCommandCount, a, 10), NewBethDefinitionIni);
			WritePrivateProfileString("ParamTypes", "Count", _itoa(g_ParamTypeCount, a, 10), NewBethDefinitionIni);
			WritePrivateProfileString("ParamTypes", "Max", _itoa((__int32)knownTypeID.size() - 1, a, 10), NewBethDefinitionIni);

			qfprintf(f, "bethesdaDefinition\n");
			__int32 used = 0;
			for (__int32 i = 0; i < (__int32)knownTypeID.size(); ++i)
				if (knownTypeID[i].typeID > InvalidTypeID)
					used++;
			qfprintf(f, "%d\n", used);
			for (__int32 i = 0; i < (__int32)knownTypeID.size(); ++i)
			{
				ObScriptParamInternal p = knownTypeID[i];
				if (p.typeID > InvalidTypeID)
				{
					char b[16];
					s.sprnt("%d;%s;%d\n", p.typeID, p.name.c_str(), p.wbType);
					qfprintf(f, s.c_str());
					_itoa(p.typeID, b, 10);
					WritePrivateProfileString("ParamTypeNames", b, p.name.c_str(), NewBethDefinitionIni);
					WritePrivateProfileString("ParamTypeWBTypes", b, _itoa(p.wbType, a, 10), NewBethDefinitionIni);
				}
			}
			qfprintf(f, "\n\n\n\n");
		}

		msg("\n\n");

		RTTI::classInfo* ci = NULL;
		// ==== Find and process NetImmerse classes
		msg("\nScanning for NetImmerse classes.\n");
		if (!(ci = RTTI::findClassInList("NiRefObject")))
			return(TRUE);
		else
			msg("\t\tFound '%s' at %x\n", "NiRefObject", ci->m_start);

		ci = NULL;

		// ==== Confirm it's a BS game
		msg("\nScanning for Bethesda Software.\n");
		if (!(ci = RTTI::findClassInList("BaseFormComponent")))
			return(TRUE);
		else
			msg("\t\tFound '%s' at %x\n", "BaseFormComponent", ci->m_start);

		ci = NULL;
		
		// Settings
		msg("\nScanning for Bethesda Software Settings.\n");
		if (!(ci = RTTI::findClassInList("Setting")))
			return(TRUE);
		else
		{
			msg("\t\tFound '%s' at %x (%d collections)\n", "Setting", ci->m_start, g_SettingCollectionVFTnames.size());
			for (size_t i = 0; i < g_SettingCollectionVFTnames.size(); ++i)
			{
				ea_t eaV = get_name_ea(0, g_SettingCollectionVFTnames[i].c_str());
				ea_t eaTo = BADADDR;
				msgR("\t\t\tFound '%s' at %x\n", g_SettingCollectionVFTnames[i].c_str(), eaV);
				if (BADADDR != eaV && BADADDR != (eaTo = get_first_dref_to(eaV)))
				{
#ifdef __EA64__
					ea_t eaN = eaV + 8 + 8;
#else
					ea_t eaN = eaV + 4 + 4;
#endif
					char tmpStr[MAXSTR]="";
					GetString(tmpStr, eaN);
					qstring t("__ICI__Setting_");
					t += qstring(tmpStr);
					if (!has_name(eaTo) || has_dummy_name(eaTo))
						set_name(eaTo, t.c_str());
					eaTo = get_next_dref_to(eaV, eaTo);
				};
			}
		}
	}
#ifndef __DEBUG
	CATCH()
#endif

	return(FALSE);
}

