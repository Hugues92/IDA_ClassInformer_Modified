
// ****************************************************************************
// File: Vftable.cpp
// Desc: Virtual function table parsing support
//
// ****************************************************************************
#include "stdafx.h"
#include "Core.h"
#include "Vftable.h"
#include "RTTI.h"
#include "pro.h"

namespace vftable
{
	int tryKnownMember(ea_t vft, ea_t eaMember, UINT iIndex, LPCSTR prefixName, ea_t parentvft, ea_t eaJump, VFMemberList* vfMemberList);
	bool IsDefault(ea_t vft, ea_t eaMember, UINT iIndex, LPCSTR szClassName, LPSTR szCurrName);
	bool IsMember(ea_t vft, ea_t eaMember, UINT iIndex, LPSTR szCurrName, LPSTR szBaseName, LPSTR* szMember);
	bool extractNames(ea_t sub, ea_t entry, UINT iIndex, LPSTR currentName, LPSTR baseName, LPSTR* memberName, LPSTR szCmnt);
	bool hasDefaultComment(ea_t entry, LPSTR cmnt, LPSTR* cmntData);

	const char *defaultMemberFormat = "Func%04X";	//	default: index
	const char *defaultNameFormat = "%s::%s";	//	default: className defaultName
	const char *defaultTypeNameFormat32 = "%s%s __thiscall %s(%s%s%s)";	//	default: int , " ", fullName, paramName
	const char *defaultTypeNameFormat64 = "%s%s __fastcall %s(%s%s%s)";	//	default: int , " ", fullName, paramName
	const char *defaultCommentBase = " (#Func ";
	const char *defaultCommentNameFormat = " (#Func %04X) %s::%s";		//	default: index, className, memberName

	VFGuessedFunc vfGuessedFunc;
};

// Attempt to get information of and fix vftable at address
// Return TRUE along with info if valid vftable parsed at address
BOOL vftable::getTableInfo(ea_t ea, vtinfo &info)
{
    ZeroMemory(&info, sizeof(vtinfo));

	// Start of a vft should have an xref and a name (auto, or user, etc).
    // Ideal flags 32bit: FF_DWRD, FF_0OFF, FF_REF, FF_NAME, FF_DATA, FF_IVL
    //dumpFlags(ea);
    flags_t flags = get_flags_novalue(ea);
	if(hasRef(flags) && has_any_name(flags) && (isEa(flags) || isUnknown(flags)))
    {
        // Get raw (auto-generated mangled, or user named) vft name
        //if (!get_name(BADADDR, ea, info.name, SIZESTR(info.name)))
        //    msg(EAFORMAT" ** vftable::getTableInfo(): failed to get raw name!\n", ea);

        // Determine the vft's method count
        ea_t start = info.start = ea;
        while (TRUE)
        {
            // Should be an ea_t offset to a function here (could be unknown if dirty IDB)
            // Ideal flags for 32bit: FF_DWRD, FF_0OFF, FF_REF, FF_NAME, FF_DATA, FF_IVL
            //dumpFlags(ea);
            flags_t indexFlags = get_flags_novalue(ea);
            if (!(isEa(indexFlags) || isUnknown(indexFlags)))
            {
                //msg(" ******* 1\n");
                break;
            }

            // Look at what this (assumed vftable index) points too
            ea_t memberPtr = getEa(ea);
            if (!(memberPtr && (memberPtr != BADADDR)))
            {
                // vft's often have a zero ea_t (NULL pointer?) following, fix it
                if (memberPtr == 0)
                    fixEa(ea);

                //msg(" ******* 2\n");
                break;
            }

            // Should see code for a good vft method here, but it could be dirty
            flags_t flags = get_flags_novalue(memberPtr);
            if (!(isCode(flags) || isUnknown(flags)))
            {
                //msg(" ******* 3\n");
                break;
            }

            if (ea != start)
            {
                // If we see a ref after first index it's probably the beginning of the next vft or something else
                if (hasRef(indexFlags))
                {
                    //msg(" ******* 4\n");
                    break;
                }

                // If we see a COL here it must be the start of another vftable
                if (RTTI::_RTTICompleteObjectLocator::isValid(memberPtr))
                {
                    //msg(" ******* 5\n");
                    break;
                }
            }

            // As needed fix ea_t pointer, and, or, missing code and function def here
            fixEa(ea);
            fixFunction(memberPtr);

            ea += sizeof(ea_t);
        };

        // Reached the presumed end of it
        if ((info.methodCount = ((ea - start) / sizeof(ea_t))) > 0)
        {
            info.end = ea;
            //msg(" vftable: "EAFORMAT"-"EAFORMAT", methods: %d\n", rtInfo.eaStart, rtInfo.eaEnd, rtInfo.uMethods);
            return(TRUE);
        }
    }

    //dumpFlags(ea);
    return(FALSE);
}


// Get relative jump target address

static ea_t getRelJmpTarget(ea_t eaAddress)
{
	BYTE bt = get_byte(eaAddress);
	if(bt == 0xEB)
	{
		bt = get_byte(eaAddress + 1);
		if(bt & 0x80)
			return(eaAddress + 2 - ((~bt & 0xFF) + 1));
		else
			return(eaAddress + 2 + bt);
	}
	else
	if(bt == 0xE9)
	{
		UINT dw = get_32bit(eaAddress + 1);
		if(dw & 0x80000000)
			return(eaAddress + 5 - (~dw + 1));
		else
			return(eaAddress + 5 + dw);
	}
	else
		return(BADADDR);
}

#define SN_constructor 1
#define SN_destructor  2
#define SN_vdestructor 3
#define SN_scalardtr   4
#define SN_vectordtr   5

qstring getNonDefaultComment(flags_t f, ea_t ea, LPCSTR defaultComment)
{
	char s[MAXSTR] = "";
	if (has_cmt(f))
	{
		get_cmt(ea, false, s, MAXSTR - 1);
		if (0 == strnicmp(defaultComment, s, MAXSTR - 1))
			strcpy_s(s, "");
		else
		if (strstr(s, vftable::defaultCommentBase) == s)
		{
			// Check Index is valid
			long av = strtol(s + strlen(vftable::defaultCommentBase), NULL, 16);
			long dv = strtol(defaultComment + strlen(vftable::defaultCommentBase), NULL, 16);
			if (av != dv)
			{
				// invalid usage of a function member
				strcpy_s(s, "");
				//msg(" "EAFORMAT" [%s] av:%x dv:%x [%s]\n", ea, defaultComment, av, dv, s);
			}
		}
		else
			strcpy_s(s, "");
	}
	qstring q = s;
	return q;

}

qstring ExtractMemberName(qstring s)
{
	qstring q;
	LPCSTR sz = s.c_str();
	if (sz)
		while (LPCSTR sep = strstr(sz, "::"))
			sz = sep + 2;
	if (sz && strlen(sz) < s.length())
		q = sz;
	else
		q = "";
	return q;
}

qstring ExtractClassName(qstring s, bool fromComment = false)
{
	qstring q = "";
	char temp[MAXSTR] = "";
	LPCSTR sz = s.c_str();
	if (fromComment && strstr(sz, " (#Func") == sz)
		sz += strlen(" (#Func 0000) ");
	strcpy_s(temp, sz);
	sz = temp;
	if (sz)
		while (LPCSTR sep = strstr(sz, "::"))
			sz = sep + 2;
		if (sz && strlen(sz) < strlen(temp) - strlen("::"))
		{
			temp[strlen(temp) - strlen(sz) - strlen("::")] = 0;
			q = temp;
		}
	return q;
}

void typeMember(ea_t eaMember, tinfo_t tif, bool edit)
{
	qstring s = "";
	func_type_data_t fi;
	if (tif.get_func_details(&fi))
	{
		fi.dump(&s);
	}
	//msg(" "EAFORMAT" ** %s : '%s' ** \n", eaMember, edit ? "typed" : "guessed", s.c_str());
}

void guessMember(ea_t eaMember)
{
	vftable::VFGuessedFunc::iterator i = vftable::vfGuessedFunc.find(eaMember);
	if (i == vftable::vfGuessedFunc.end())
	{
		bool guessed = false;
		tinfo_t tif;
		if (!get_tinfo2(eaMember, &tif))
			if (guess_tinfo2(eaMember, &tif) && tif.is_func())
			{
				typeMember(eaMember, tif, false);
				guessed = true;
			}
			else
				msg(" "EAFORMAT" ** not guessed ** \n", eaMember);
		else
		{
			typeMember(eaMember, tif, true);
			guessed = true;
		}
		vftable::vfGuessedFunc.insert({ eaMember, guessed });
	}
}

bool IsAssociatedClass(bool& isParent, bool& isDescendant, RTTI::classInfo* ci, qstring aClass)
{
	isParent = isDescendant = false;
	if (0 == aClass.length())
		return false;
	bool found = (0 == stricmp(ci->m_cTypeName, aClass.c_str()));

	RTTI::classInfo* aCI = ci;
	while (!found && aCI->m_parents.size())
	{
		aCI = &RTTI::classList[aCI->m_parents[0]];
		if (aCI && 0 == stricmp(aCI->m_cTypeName, aClass.c_str()))
		{
			found = true;
			isParent = true;
		}
	}
	if (!found)
	{
		aCI = RTTI::findClassInList(aClass.c_str());
		if (aCI)
			while (!found && aCI->m_parents.size())
			{
				aCI = &RTTI::classList[aCI->m_parents[0]];
				if (aCI && 0 == stricmp(aCI->m_cTypeName, ci->m_cTypeName))
				{
					found = true;
					isDescendant = true;
				}
			}
	}
	return found;
}

vftable::EntryInfo::EntryInfo(UINT iIndex, ea_t eaVft, ea_t eaParentVft, LPCSTR szClassName, VFMemberList* parentList)
{
	EntryInfo();

	RTTI::classInfo* ci = RTTI::findClassInList(szClassName);
	if (!ci)
	{
		msgR("	*** ci is null for %s\r", szClassName);
		return;
	}
	assert(ci);

	qstring defaultComment = "";
	index = iIndex;
	className = szClassName;
	MakeDefaultName(defaultName);
	MakeDefaultComment(defaultComment);
	vft = eaVft;
	entry = vft + index * sizeof(ea_t);
	parentVft = eaParentVft;
	if (BADADDR != parentVft && parentList && parentList->size() > iIndex)
	{
		vftable::EntryInfo* p = &(*parentList)[iIndex];
		member = p->member;
		jump = p->jump;
		memberFlags = p->memberFlags;
		entryFlags = p->entryFlags;
		jumpFlags = p->jumpFlags;
		className = p->className;
		memberName = p->memberName;
		returnName = p->returnName;
		paramName = p->paramName;
		fullName = p->fullName;
		comment = p->comment;
		jumpComment = p->jumpComment;
		typeName = p->typeName;
		jumpTypeName = p->jumpTypeName;
		isDefault = p->isDefault;
		isInherited = true;
		isIdentical = true;
		isMember = p->isMember;
		isOutOfHierarchy= p->isOutOfHierarchy;
	}
	else
	{
		member = BADADDR;
		jump = BADADDR;
		memberFlags = 0;
		entryFlags = 0;
		jumpFlags = 0;
		memberName = "";
		returnName = "";
		paramName = "";
		fullName = "";
		comment = "";
		jumpComment = "";
		typeName = "";
		jumpTypeName = "";
		isDefault = false;
		isInherited = false;
		isIdentical = false;
		isMember = false;
		isOutOfHierarchy = false;
	}
	ea_t newMember = getEa(entry);
	bool unique = true;
	for (ea_t i = ci->m_start; i < ci->m_end; i += sizeof(ea_t))
	{
		ea_t ea;
		if (i != entry && (ea = getEa(i) == newMember))
		{
			unique = false;
			break;
		}
	}

	ea_t newJump = BADADDR;
	ea_t next = BADADDR;
	while ((next = getRelJmpTarget(newMember)) != BADADDR)
	{
		// Should be code
		flags_t flags = getFlags(newMember);
		if (!isCode(flags))
			fixFunction(newMember);
		if (BADADDR == newJump)
			newJump = newMember;
		newMember = next;
	}
	isIdentical = member == newMember;

	entryFlags = getFlags(entry);

	// Check if we have a non default comment somewhere
	qstring currComment = "";
	qstring newComment = getNonDefaultComment(entryFlags, entry, defaultComment.c_str());
	if (newComment.length())
		currComment = newComment;
	else if (BADADDR != member)
	{
		newComment = getNonDefaultComment(memberFlags, member, defaultComment.c_str());
		if (newComment.length())
			currComment = newComment;
	}

	if (!IsIdentical())
	{
		className = szClassName;
		fullName = "";
		isOutOfHierarchy = false;

		member = newMember;
		memberFlags = getFlags(member);
		newComment = getNonDefaultComment(memberFlags, member, defaultComment.c_str());
		if (newComment.length() && 0 == currComment.length())
			currComment = newComment;
	}

	if (jump != newJump)
	{
		jump = newJump;
		jumpComment = "";
		if (BADADDR != newJump)
		{
			jumpFlags = getFlags(jump);
			while ((next = getRelJmpTarget(newJump)) != BADADDR)
			{
				flags_t f = getFlags(newJump);
				newComment = getNonDefaultComment(f, newJump, defaultComment.c_str());
				if (0 == currComment.length() && newComment.length())
					currComment = newComment;
				if (jump == newJump && comment != newComment)
					jumpComment = newComment;
				newJump = next;
			}
			if (0 == currComment.length())
				currComment = defaultComment;
			newJump = jump;
		}
	}
	if (0 == currComment.length())
		newComment = defaultComment;
	else
		newComment = currComment;

	// extract valid member name from comment if needed
	qstring newMemberName = memberName.length() ? memberName : "";
	if (0 == newMemberName.length())
	{
		bool isParent = false;
		bool isDescendant = false;
		qstring newClassName = ExtractClassName(newComment, true);
		if (IsAssociatedClass(isParent, isDescendant, ci, newClassName))
			newMemberName = ExtractMemberName(newComment);
	}

	if (!IsIdentical())
	{
		// Extract current name from member
		memberFlags = getFlags(member);
		qstring newFullName = "";
		qstring currentFullName = get_true_name(member);

		if (get_func(member) && has_name(memberFlags) && !has_dummy_name(memberFlags))
		{
			newFullName = get_true_name(member);
			// is it a demangled name ?
			if (newFullName.length() && newFullName[0] == '?')
			{
				typeName = newFullName;
				RTTI::getTypeName(typeName);
			}
			qstring currentName = unique ? ExtractMemberName(newFullName) : "";
			qstring currentClass = unique ? ExtractClassName(newFullName) : "";

			// lookup currentClassName in hierarchy, unless already not unique
			isOutOfHierarchy = !unique;
			bool isParent = false, isDescendant = false;
			if (!isOutOfHierarchy)
			{
				isOutOfHierarchy = !IsAssociatedClass(isParent, isDescendant, ci, currentClass);
				if (isDescendant)
					currentClass = szClassName;	// member should be named after the first class that uses it
			}
			// if memberName from a parent use it as our member name
			if (!IsOutOfHierarchy())
			{
				if (currentName.length() && currentName != defaultName)
					newMemberName = currentName;
				else
					isDefault = currentName.length();
				if (isDefault)
					MakeNewFullName(newFullName, newMemberName);
				if (currentClass.length())
					className = currentClass;
				else
				{
					fullName = newFullName;
				}
			}
		}
		else if (memberName.length())
			MakeFullName(newFullName);
		else
		{
			if (newMemberName.length() && newMemberName != defaultName)
			{
				memberName = newMemberName;
				MakeFullName(newFullName);
			}
			else
				MakeDefaultFullName(newFullName);
		}

		if (newFullName.length() && 0 == newMemberName.length())
			newMemberName = ExtractMemberName(newFullName);
		if (newMemberName.length() && newMemberName != defaultName)
		{
			if (memberName != newMemberName)
			{
				memberName = newMemberName;
				RTTI::classInfo* aCI = ci;
				while (aCI->m_parents.size())
				{
					UINT k = aCI->m_parents[0];
					VFMemberList* aML = &RTTI::vfTableList[k];
					if (aML && aML->size() > iIndex)
					{
						vftable::EntryInfo* aEI = &(*aML)[iIndex];
						if (0 == aEI->memberName.length() || aEI->memberName == defaultName)
							aEI->memberName = memberName;
					}
					aCI = &RTTI::classList[k];
				}
			}
			MakeComment(comment);
		}
		else
		{
			MakeDefaultComment(comment);
			isDefault = newMemberName == defaultName;
			if (newMemberName.length())
				memberName = newMemberName;
		}
		if (newFullName.length() && 0 == fullName.length())
			fullName = newFullName;
		isMember = memberName.length() && unique && !isOutOfHierarchy;
		
		guessMember(member);

		if (unique && !isOutOfHierarchy)	// forward comment
		{
			newJump = jump;
			while ((next = getRelJmpTarget(newJump)) != BADADDR)
			{
				flags_t f = getFlags(newJump);
				newComment = getNonDefaultComment(f, newJump, defaultComment.c_str());
				if (0 == newComment.length())
					set_cmt(newJump, comment.c_str(), false);
				set_name(newJump, "");	// so it gets recalculated to j_...
				newJump = next;
			}
			if (currentFullName != fullName)
				set_name(member, fullName.c_str());
			newComment = getNonDefaultComment(memberFlags, member, defaultComment.c_str());
			if (0 == newComment.length())
				set_cmt(member, comment.c_str(), false);
		}
		else
			isDefault = false;
	}

	newComment = getNonDefaultComment(entryFlags, entry, defaultComment.c_str());
	if (0 == newComment.length())
		set_cmt(entry, comment.c_str(), false);
};

bool vftable::IsClass(LPCSTR szClassName, LPSTR szCurrName, bool translate)
{
	bool result = false;
	char * szBase = szCurrName;
	//if (translate) msg("  ** IsClass? '%s' for '%s' **\n", szBase, szClassName);
	while (stristr(szBase, "j_") == szBase)
	{
		//msg("  "EAFORMAT" ** Jumping member %s for %s **\n", eaMember, szBase, szClassName);
		szBase += 2;
	}
	result = (stristr(szBase, szClassName) == szBase);
	if (result && strlen(szBase) > strlen(szClassName)+2)
	{
		LPSTR sz = szBase + strlen(szClassName);
		if (translate)
			result = strstr(sz, "::");
		else
			result = sz[0] == ':' && sz[1] == ':';
		//msg("  ** IsClass? {%1d} '%s' for '%s' in [%s] **\n", result, sz, szClassName, szCurrName);
	}
	return result;
}

bool vftable::IsDefault(ea_t vft, ea_t eaMember, UINT iIndex, LPCSTR szClassName, LPSTR szCurrName)
{

	bool isJump = false;
	char * szBase = szCurrName;
	while (stristr(szBase, "j_") == szBase)
	{
		//msg("  "EAFORMAT" ** Jumping member %s for %s **\n", eaMember, szBase, szClassName);
		isJump = true;
		szBase += 2;
	}
	char demangledName[MAXSTR] = "";
	if (getPlainTypeName(szBase, demangledName))
	{
		//msg("  ** from '%s' to '%s'\n", szBase, demangledName);
		szBase = demangledName;
	}

	bool isClass = false;
	bool isUnderscore = false;
	bool isColon = false;
	bool isDblColon = false;
	bool isDot;
	bool isUnk = false;
	bool isFunc = false;
	char szGoodName[MAXSTR];
	strcpy_s(szGoodName, MAXSTR - 1, szClassName);
	while (LPSTR sep = strstr(szGoodName, "::"))
	{
		sep[0] = '_';
		sep[1] = '_';
	}
	if (stristr(szBase, szGoodName) == szBase)
	{
		//msg("  "EAFORMAT" ** IsClass member %s for %s **\n", eaMember, szBase, szClassName);
		isClass = true;
		szBase += strlen(szGoodName);
		if (szBase && szBase[0] == '_')
		{
			//msg("  "EAFORMAT" ** Underscored member %s for %s **\n", eaMember, szBase, szClassName);
			isUnderscore = true;
			szBase++;
			if (szBase && szBase[0] == '_')
			{
				//msg("  "EAFORMAT" ** DblUnderscored member %s for %s **\n", eaMember, szBase, szClassName);
				isUnderscore = true;
				szBase++;
			}
		}
		else if (szBase && szBase[0] == ':')
		{
			//msg("  "EAFORMAT" ** Colon member %s for %s **\n", eaMember, szBase, szClassName);
			isColon = true;
			szBase++;
			if (szBase && szBase[0] == ':')
			{
				//msg("  "EAFORMAT" ** DblColon member %s for %s **\n", eaMember, szBase, szClassName);
				isDblColon = true;
				isColon = false;
				szBase++;
			}
		}
		else if (szBase && szBase[0] == '.')
		{
			//msg("  "EAFORMAT" ** Dot member %s for %s **\n", eaMember, szBase, szClassName);
			isDot = true;
			szBase++;
		}
	}
	if (isClass && (isUnderscore || isColon || isDblColon || isDot))
	{
		if (stristr(szBase, "unk") == szBase)
		{
			//msg("  "EAFORMAT" ** Unk member %s for %s **\n", eaMember, szBase, szClassName);
			isUnk = true;
			szBase += strlen("unk");
			if (szBase && szBase[0] == '_')
			{
				szBase++;
				//msg("  "EAFORMAT" ** Unk underscored member %s for %s **\n", eaMember, szBase, szClassName);
			}
		}
		if (stristr(szBase, "Func") == szBase)
		{
			//msg("  "EAFORMAT" ** Func member %s for %s **\n", eaMember, szBase, szClassName);
			isFunc = true;
			szBase += strlen("Func");
			if (szBase && szBase[0] == '_')
			{
				//msg("  "EAFORMAT" ** Func underscored member %s for %s **\n", eaMember, szBase, szClassName);
				szBase++;
			}
		}
		if (isUnk || isFunc)
		{
			int number = (int)strtol(szBase, NULL, 16);
			if (number == iIndex) {
				//msg("  "EAFORMAT" ** Hexadecimal member %s for %s **\n", eaMember, szBase, szClassName);
				return true;
			}
		}
	}
	return false;
}

bool vftable::IsMember(ea_t vft, ea_t eaMember, UINT iIndex, LPSTR szCurrName, LPSTR szBaseName, LPSTR *szMember)
{
	if (!szCurrName)
		return false;

	bool isJump = false;
	LPSTR szSep = NULL;
	LPSTR szLastSep = NULL;
	*szMember = szCurrName;
	//msg("  "EAFORMAT" ** Checking member '%s' **\n", eaMember, *szMember);
	while (stristr(*szMember, "j_") == *szMember)
	{
		//msg("  "EAFORMAT" ** Jumping member '%s' **\n", eaMember, *szMember);
		isJump = true;
		*szMember += 2;
	}

	char demangledName[MAXSTR] = "";
	if (getPlainTypeName(*szMember, demangledName))
	{
		//msg("  ** from '%s' to '%s'\n", *szMember, demangledName);
		*szMember = demangledName;
	}

	bool isMember = false;
	bool isUnk = false;
	bool isFunc = false;
	while (szSep = strstr(*szMember, "::"))
	{
		//msg("  "EAFORMAT" ** DblColon member '%s' **\n", eaMember, szSep, *szMember);
		isMember = true;
		*szMember = szSep + 2;
		szLastSep = szSep;
	}
	while (szSep = strstr(*szMember, "__"))
	{
		//msg("  "EAFORMAT" ** DblColon member '%s' **\n", eaMember, szSep, *szMember);
		isMember = true;
		*szMember = szSep + 2;
		szLastSep = szSep;
	}
	while (szSep = strstr(*szMember, ":"))
	{
		//msg("  "EAFORMAT" ** Colon member '%s' **\n", eaMember, szSep, *szMember);
		isMember = true;
		*szMember = szSep + 1;
		szLastSep = szSep;
	}
	while (szSep = strstr(*szMember, "."))
	{
		//msg("  "EAFORMAT" ** Dot member '%s' **\n", eaMember, szSep, *szMember);
		isMember = true;
		*szMember = szSep + 1;
		szLastSep = szSep;
	}
	if (isMember && szBaseName && szLastSep)
	{
		UINT offsetJump = isJump ? 2 : 0;
		strncpy_s(szBaseName, MAXSTR - 1, szCurrName + offsetJump, strlen(szCurrName) - strlen(szLastSep) - offsetJump);
	}
	//msg("  "EAFORMAT" ** (%d), Sep:'%s' Member:'%s' Base:'%s' BaseLen:%d **\n", eaMember, isMember, szLastSep, *szMember, szBaseName, szLastSep ? strlen(szCurrName) - strlen(szLastSep) : 0);
	return isMember;
}

char * get_any_indented_cmt(ea_t entry)
{
	static char szTemp[MAXSTR];
	strcpy_s(szTemp, "");
	if (0 < get_cmt(entry, false, szTemp, MAXSTR - 1))
		return szTemp;
	else
		if (0 < get_cmt(entry, true, szTemp, MAXSTR - 1))
			return szTemp;
		else
			return "";
}

bool vftable::hasDefaultComment(ea_t entry, LPSTR cmnt, LPSTR* cmntData)
{
	flags_t flags = getFlags(entry);

	if (has_cmt(flags))
	{
		strcpy_s(cmnt, MAXSTR - 1, get_any_indented_cmt(entry));
		//msg("  "EAFORMAT" ** Comment '%s' **\n", entry, cmnt);
		if (cmntData && strstr(cmnt, " (#Func ") == cmnt)
		{
			//msg("  "EAFORMAT" ** Default comment '%s' **\n", entry, cmnt);
			*cmntData = strchr(cmnt, ')') + 2;
			return true;
		}
	}
	//else
	//	msg("  "EAFORMAT" ** No comment **\n", entry);
	return false;
}

bool vftable::extractNames(ea_t sub, ea_t entry, UINT iIndex, LPSTR currentName, LPSTR baseName, LPSTR* memberName, LPSTR cmnt)
{
	bool isMember = false;
	flags_t flags = getFlags(sub);

	LPSTR cmntData = NULL;
	if (get_func(sub) && has_name(flags) && !has_dummy_name(flags))
	{
		qstring cn = get_true_name(sub);
		if (cn.c_str())
			strncpy(currentName, cn.c_str(), (MAXSTR - 1));
		//msg("  "EAFORMAT" ** Processing %s at %08X **\n", sub, currentName, entry);
		isMember = IsMember(entry, sub, iIndex, currentName, baseName, memberName);
		if (hasDefaultComment(entry, cmnt, &cmntData))
			if (!isMember)
				isMember = IsMember(entry, sub, iIndex, cmntData, baseName, memberName);
	}
	else
		hasDefaultComment(entry, cmnt, &cmntData);
	//msg("  "EAFORMAT" ** Extracted names: current:'%s' base:'%s' member:'%s' comment:'%s' **\n", sub, currentName, baseName, *memberName, cmnt);
	return isMember;
}

// Try to identify and place known class member types
int vftable::tryKnownMember(ea_t vft, ea_t eaMember, UINT iIndex, LPCSTR prefixName, ea_t parentvft, ea_t eaJump, VFMemberList* vfMemberList)
{
	int iType = 0;
	char szClassName[MAXSTR] = "";
	if (strlen(prefixName) > (MAXSTR - 2))
	{
		msgR("  "EAFORMAT" ** Class Name too long!\n", vft);
		return iType;
	}
	strcpy_s(szClassName, MAXSTR - 1, prefixName);

	//#define IsPattern(Address, Pattern) (find_binary(Address, Address+(SIZESTR(Pattern)/2), Pattern, 16, (SEARCH_DOWN | SEARCH_NOBRK | SEARCH_NOSHOW)) == Address)

	if (eaMember && (eaMember != BADADDR))
	{
		//char szCurrName[MAXSTR] = "";
		//char szCurrParentName[MAXSTR] = "";
		//char szParentName[MAXSTR] = "";
		//char szNewName[MAXSTR] = "";
		//LPSTR szTemp = NULL;
		//::qsnprintf(szNewName, MAXSTR - 1, "%s::Func%04X", szClassName, iIndex);
		//szNewName[MAXSTR - 1] = 0;

		//flags_t flags = getFlags((ea_t)eaMember);
		//flags_t vftflags = getFlags(vft);

		////msg("%s  "EAFORMAT" ** Processing member %s (%d) at "EAFORMAT" from "EAFORMAT" ["EAFORMAT"] **\n", eaJump != BADADDR ? "\t" : "", eaMember, szNewName, iIndex, vft, parentvft, flags);

		//char szCmnt[MAXSTR] = "";
		//bool isDefaultCmnt = hasDefaultComment(vft, szCmnt, &szTemp) || (0 == strlen(szCmnt));
		////msg("  "EAFORMAT" ** Comment '%s' is default ? %d **\n", eaMember, szCmnt, isDefaultCmnt);

		//// Check if it has a default name
		//bool isDefault = false;
		//bool isMember = false;
		//LPSTR szBaseName = 0;
		//isMember = extractNames(eaMember, vft, iIndex, szCurrName, szParentName, &szBaseName, szCmnt);
		//if (has_name(flags) && !has_dummy_name(flags))
		//{
		//	isDefault = IsDefault(vft, eaMember, iIndex, szClassName, szCurrName);
		//	if (isDefault)
		//	{
		//		if (parentvft != BADADDR)
		//		{
		//			ea_t parentMember = parentvft + iIndex*sizeof(ea_t);
		//			ea_t parentSub;
		//			if (getVerify_t(parentMember, parentSub))
		//				isMember = extractNames(parentSub, parentMember, iIndex, szCurrParentName, szParentName, &szBaseName, szCmnt);
		//			if (isMember)
		//				::qsnprintf(szNewName, MAXSTR - 1, "%s::%s", szClassName, szBaseName);
		//		}
		//	}
		//	else if (!isMember)
		//	{
		//		if (parentvft != BADADDR)
		//		{
		//			ea_t parentMember = parentvft + iIndex*sizeof(ea_t);
		//			ea_t parentSub;
		//			if (getVerify_t(parentMember, parentSub))
		//				isMember = extractNames(parentSub, parentMember, iIndex, szCurrParentName, szParentName, &szBaseName, szCmnt);
		//			if (isMember) {
		//				::qsnprintf(szNewName, MAXSTR - 1, "%s::%s", szParentName, szBaseName);
		//				//msg("  "EAFORMAT" ** Processing parent member '%s' at %08X **\n", eaMember, szNewName, parentvft);
		//				isDefault = true;
		//			}
		//		}
		//	}
		//}
		//if (isMember && !isDefault)
		//	::qsnprintf(szNewName, (MAXSTR - 1), "%s::%s", szParentName, szBaseName);

		//::qsnprintf(szCmnt, MAXSTR - 1, " (#Func %04X) %s", iIndex, szNewName);

		EntryInfo entryInfo = EntryInfo(iIndex, vft - iIndex * sizeof(ea_t), parentvft, prefixName, vfMemberList);
		if (vfMemberList->size()>iIndex)
			(*vfMemberList)[iIndex] = entryInfo;
		else
			vfMemberList->push_back(entryInfo);

		//// Skip if it already has a non default name
		//if (!has_name(entryInfo.memberFlags) || has_dummy_name(entryInfo.memberFlags) || isDefault)
		//{
		//	// Should be code
		//	if (!isCode(flags))
		//	{
		//		fixFunction(eaMember);
		//		flags = getFlags((ea_t)eaMember);
		//	}
		//	if (isCode(flags))
		//	{
		//		ea_t eaAddress = getRelJmpTarget(eaMember);

		//		if(eaAddress != BADADDR)
		//		{
		//			return(tryKnownMember(vft, eaAddress, iIndex, prefixName, parentvft, eaMember, vfMemberList));
		//		}
		//		else {
		//			if (eaJump != BADADDR)
		//				set_name(eaJump, "", SN_NOWARN);	// will recalc the j_Name when Name is updated
		//			guessMember(eaMember);
		//			set_name(eaMember, szNewName, SN_NOWARN);
		//			if (eaJump != BADADDR)
		//				set_cmt(eaJump, szCmnt, false);
		//			//msg("%s ="EAFORMAT" ** Processed member %s (%d) at "EAFORMAT" from "EAFORMAT" ["EAFORMAT"] **\n", eaJump != BADADDR ? "\t" : "", eaAddress, szNewName, iIndex, vft, parentvft, flags);
		//		}
		//		if (isDefaultCmnt)
		//			set_cmt(vft, szCmnt, false);
		//	}
		//	else
		//		msg(" "EAFORMAT" ** Not code at this member! **\n", eaMember);
		//}
		//else
		//{
		//	guessMember(eaMember);
		//	if (isDefaultCmnt)
		//	{
		//		set_cmt(vft, szCmnt, false);
		//	}
		//}
		//char sz[MAXSTR] = "";
		//isDefaultCmnt = hasDefaultComment(eaMember, sz, &szTemp) || (0 == strlen(sz));
		//if (isDefaultCmnt)
		//	set_cmt(vft, szCmnt, false);

		////msg("  "EAFORMAT" ** Done member '%s' at %08X (%s) **\n", eaMember, szNewName, vft, szCmnt);
	}

	return(iType);
}


/*
TODO: On hold for now.
Do we really care about detected ctors and dtors?
Is it helpful vs the problems of naming member functions?
*/


// Process vftable member functions

// TODO: Just try the fix missing function code
void vftable::processMembers(LPCTSTR lpszName, ea_t eaStart, ea_t* eaEnd, LPCTSTR prefixName, ea_t parentvft, UINT parentCount, VFMemberList* vfMemberList)
{
	ea_t eaAddress = eaStart;
	ea_t eaShorterEnd = BADADDR;
	UINT iIndex = 0;
	UINT iCount = (*eaEnd - eaStart) / sizeof(ea_t);

	//msg(" "EAFORMAT" to "EAFORMAT" as '%s' (%s) for %d from "EAFORMAT" : %d\n", eaStart, *eaEnd, lpszName, prefixName, iCount, parentvft, parentCount);

	while (eaAddress < *eaEnd)
	{
		ea_t eaMember;
		if (getVerify_t(eaAddress, eaMember))
		{
			// Missing/bad code?
			if(!get_func(eaMember))
			{
				//msg(" "EAFORMAT" ** No member function here! Start:"EAFORMAT" End:"EAFORMAT" as '%s' %d of %d Parent: ["EAFORMAT" : %d] **\n", eaMember, eaStart, *eaEnd, lpszName, iIndex, iCount, parentvft, parentCount);
				if (BADADDR == eaShorterEnd)
					eaShorterEnd = eaAddress;
				//fixFunction(eaMember);
			}
			else
			{
				tryKnownMember(eaAddress, eaMember, iIndex++, prefixName, (iIndex < parentCount) ? parentvft : BADADDR, BADADDR, vfMemberList);
				eaShorterEnd = BADADDR;
			}
		}
		else
			msg(" "EAFORMAT" ** Failed to read member pointer! **\n", eaAddress);

		eaAddress += sizeof(ea_t);
	};
	if (BADADDR != eaShorterEnd) {
		*eaEnd = eaShorterEnd;
		//msg(" "EAFORMAT" ** Shortened! **\n", eaShorterEnd);
	}
}

ea_t vftable::getMemberName(LPSTR name, ea_t eaAddress)
{
	ea_t eaMember = BADADDR;
	bool found = false;
	char szTemp[MAXSTR] = "";
	strcpy_s(name, MAXSTR - 1, "");
	//msg("  "EAFORMAT" GetMemberName:'%s' "EAFORMAT"\n", eaMember, name, eaAddress);
	if (getVerify_t(eaAddress, eaMember))
	{
		// Missing/bad code?
		if (!get_func(eaMember))
			fixFunction(eaMember);
		if (!get_func(eaMember))
		{
			msg(" "EAFORMAT" ** No member function here! **\n", eaMember);
			eaMember = BADADDR;
			return eaMember;
		}

		// E9 xx xx xx xx   jmp   xxxxxxx
		BYTE Byte = get_byte(eaMember);
		if ((Byte == 0xE9) || (Byte == 0xEB))
		{
			//msg(" !"EAFORMAT" GetMemberName:'%s' "EAFORMAT"\n", eaMember, name, eaAddress);
			eaAddress = eaMember;
		}
		flags_t flags = getFlags(eaAddress);
		if (has_cmt(flags))
		{
			get_cmt(eaAddress, false, szTemp, MAXSTR - 1);
			if (szTemp == strstr(szTemp, " (#Func "))
			{
				char * szResult = strchr(szTemp, ')') + 2;
				strcpy_s(name, MAXSTR - 1, szResult);
				found = true;
				//msg(" *"EAFORMAT" GetMemberName:'%s' "EAFORMAT" %d\n", eaMember, name, eaAddress, flags);
			}
		}
		if (!found)
		{
			qstring cn = get_true_name(eaMember);
			if (cn.c_str())
				strncpy(szTemp, cn.c_str(), (MAXSTR - 1));
			strcpy_s(name, MAXSTR - 1, szTemp);
		}
	}
	else
	{
		msg(" "EAFORMAT" ** Failed to read member pointer! **\n", eaAddress);
		eaMember = BADADDR;
	}
	//msg(" ="EAFORMAT" GetMemberName:'%s' "EAFORMAT"\n", eaMember, name, eaAddress);
	return eaMember;
}

ea_t vftable::getMemberShortName(LPSTR name, ea_t eaAddress)
{
	bool found = false;
	char szTemp[MAXSTR] = "";
	ea_t eaMember = getMemberName(szTemp, eaAddress);
	LPCSTR sz = strstr(szTemp, "::");
	if (sz)
		strcpy_s(name, MAXSTR - 1, sz + 3);
	else
		strcpy_s(name, MAXSTR - 1, "");
	return eaMember;
}