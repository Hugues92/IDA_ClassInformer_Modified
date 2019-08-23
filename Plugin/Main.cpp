
// ****************************************************************************
// File: Core.cpp
// Desc: Class Informer
//
// ****************************************************************************
#include "stdafx.h"
#include "Main.h"
#include "Vftable.h"
#include "RTTI.h"
#include "ObScript.h"
#include "MainDialog.h"
#include <map>
//
#include <WaitBoxEx.h>
#include <IdaOgg.h>

typedef std::map<ea_t, std::string> STRMAP;

// Netnode constants
const static char NETNODE_NAME[] = {"$ClassInformer_node"};
const char NN_DATA_TAG  = 'A';
const char NN_TABLE_TAG = 'S';

// Our netnode value indexes
enum NETINDX
{
    NIDX_VERSION,   // ClassInformer version
    NIDX_COUNT      // Table entry count
};

// VFTable entry container (fits in a netnode MAXSPECSIZE size)
#pragma pack(push, 1)
struct TBLENTRY
{
    ea_t vft;
    WORD methods;
    WORD flags;
    WORD strSize;
    char str[MAXSPECSIZE - (sizeof(ea_t) + (sizeof(WORD) * 3))]; // Note: IDA MAXSTR = 1024
};
#pragma pack(pop)

// Line background color for non parent/top level hierarchy lines
// TOOD: Assumes text background is white. A way to make these user theme/style color aware?
#define GRAY(v) RGB(v,v,v)
static const bgcolor_t NOT_PARENT_COLOR = GRAY(235);

// === Function Prototypes ===
static BOOL processStaticTables();
static void showEndStats();
static BOOL getRttiData(SegSelect::segments *segList);

// === Data ===
static TIMESTAMP s_startTime = 0;
static HMODULE myModuleHandle = NULL;
static UINT staticCCtorCnt = 0, staticCppCtorCnt = 0, staticCDtorCnt = 0;
static UINT startingFuncCount = 0, staticCtorDtorCnt = 0;
static UINT colCount = 0, missingColsFixed = 0, vftablesFixed = 0;
static BOOL initResourcesOnce = FALSE;
static int  chooserIcon = 0;
static netnode *netNode = NULL;
static eaList colList;

// Options
BOOL optionPlaceStructs	 = TRUE;
BOOL optionProcessStatic = TRUE;
BOOL optionAudioOnDone   = TRUE;
BOOL optionClean         = FALSE;
BOOL optionFullClear     = FALSE;

UINT optionIterLevels    = 10;
BOOL optionDumpIdentical = FALSE;

// Get IDA 32 bit value with verification
template <class T> BOOL getVerify32_t(ea_t eaPtr, T &rValue)
{
	// Location valid?
	if (is_loaded(eaPtr))
	{
		// Get 32bit value
		rValue = (T)get_32bit(eaPtr);
		return(TRUE);
	}

	return(FALSE);
}

// Get IDA 64 bit value with verification
template <class T> BOOL getVerify64_t(ea_t eaPtr, T &rValue)
{
	// Location valid?
	if (is_loaded(eaPtr))
	{
		// Get 64bit value
		rValue = (T)get_64bit(eaPtr);
		return(TRUE);
	}

	return(FALSE);
}

#ifdef __EA64__
#define getVerify_t getVerify64_t
#else
#define getVerify_t getVerify32_t
#endif

// Returns TRUE if there is a name at address that is unique (I.E. user, or from PDB, etc., and not IDA auto-generated)
inline BOOL hasUniqueName(ea_t ea) { return(has_name(get_flags_ex(ea, 0))); }

static void freeWorkingData()
{
    try
    {
        RTTI::freeWorkingData();
        colList.clear();

        if (netNode)
        {
            delete netNode;
            netNode = NULL;
        }
    }
    CATCH()
}

// Initialize
int idaapi init()
{
	// Want the table entry structure to fit the max netnode size
	CASSERT(sizeof(TBLENTRY) == 1024);

	if (ph.id == PLFM_386) // (strcmp(inf.procname, "metapc") == 0) // (ph.id == PLFM_386)
	{
		GetModuleHandleEx((GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT | GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS), (LPCTSTR)&init, &myModuleHandle);
		return PLUGIN_KEEP;
	}

	return PLUGIN_SKIP;
}

// Uninitialize
// Normally doesn't happen as we need to stay resident for the modal windows
void idaapi term()
{
	try
	{
		OggPlay::endPlay();
		freeWorkingData();

		if (initResourcesOnce)
		{
			if (chooserIcon)
			{
				free_custom_icon(chooserIcon);
				chooserIcon = 0;
			}

			Q_CLEANUP_RESOURCE(ClassInformerRes);
			initResourcesOnce = FALSE;
		}
	}
	CATCH()
}


// Init new netnode storage
static void newNetnodeStore()
{
    // Kill any existing store data first
    netNode->altdel_all(NN_DATA_TAG);
    netNode->supdel_all(NN_TABLE_TAG);

    // Init defaults
    netNode->altset_idx8(NIDX_VERSION, MY_VERSION, NN_DATA_TAG);
    netNode->altset_idx8(NIDX_COUNT,   0,          NN_DATA_TAG);
}

static WORD getStoreVersion(){ return((WORD)netNode->altval_idx8(NIDX_VERSION, NN_DATA_TAG)); }
static UINT getTableCount(){ return(netNode->altval_idx8(NIDX_COUNT, NN_DATA_TAG)); }
static BOOL setTableCount(UINT count){ return(netNode->altset_idx8(NIDX_COUNT, count, NN_DATA_TAG)); }
static BOOL getTableEntry(TBLENTRY &entry, UINT index){ return(netNode->supval(index, &entry, sizeof(TBLENTRY), NN_TABLE_TAG) > 0); }
static BOOL setTableEntry(TBLENTRY &entry, UINT index){ return(netNode->supset(index, &entry, (offsetof(TBLENTRY, str) + entry.strSize), NN_TABLE_TAG)); }

// Add an entry to the vftable list
void addTableEntry(UINT flags, ea_t vft, int methodCount, LPCTSTR format, ...)
{
	TBLENTRY e;
	e.vft = vft;
	e.methods = methodCount;
	e.flags = flags;

	va_list vl;
	va_start(vl, format);
	vsnprintf_s(e.str, sizeof(e.str), SIZESTR(e.str), format, vl);
	va_end(vl);
	e.strSize = (WORD) (strlen(e.str) + 1);

	UINT count = getTableCount();
	setTableEntry(e, count);
	setTableCount(++count);
}


// RTTI list chooser
static const char LBTITLE[] = { "[Class Informer]" };
static const UINT LBCOLUMNCOUNT = 5;
static const int LBWIDTHS[LBCOLUMNCOUNT] = { (8 | CHCOL_HEX), (4 | CHCOL_DEC), 3, 19, 500 };
static const char *const LBHEADER[LBCOLUMNCOUNT] =
{
	"Vftable",
	"Methods",
	"Flags",
	"Type",
	"Hierarchy"
};


class rtti_chooser : public chooser_multi_t
{
public:
	rtti_chooser() : chooser_multi_t(CH_QFTYP_DEFAULT, LBCOLUMNCOUNT, LBWIDTHS, LBHEADER, LBTITLE)
	{
		#ifdef __EA64__
		// Setup hex address display to the minimal size needed plus a leading zero
		UINT count = getTableCount();
		ea_t largestAddres = 0;
		for (UINT i = 0; i < count; i++)
		{
			TBLENTRY e; e.vft = 0;
			getTableEntry(e, i);
			if (e.vft > largestAddres)
				largestAddres = e.vft;
		}

		char buffer[32];
		int digits = (int) strlen(_ui64toa(largestAddres, buffer, 16));
		if (++digits > 16) digits = 16;
		sprintf_s(addressFormat, sizeof(buffer), "%%0%uI64X", digits);
		#endif

		// Chooser icon
		icon = chooserIcon;
	}

	virtual const void *get_obj_id(size_t *len) const
	{
		*len = sizeof(LBTITLE);
		return LBTITLE;
	}

	virtual size_t get_count() const { return (size_t)getTableCount(); }

	virtual void get_row(qstrvec_t *cols_, int *icon_, chooser_item_attrs_t *attributes, size_t n) const
	{
		try
		{
			if (netNode)
			{
				// Generate the line
				TBLENTRY e;
				getTableEntry(e, (UINT)n);

				// vft address
				qstrvec_t &cols = *cols_;
				#ifdef __EA64__
				cols[0].sprnt(addressFormat, e.vft);
				#else
				cols[0].sprnt(EAFORMAT, e.vft);
				#endif

				// Method count
				if (e.methods > 0)
					cols[1].sprnt("%u", e.methods); // "%04u"
				else
					cols[1].sprnt("???");

				// Flags
				char flags[4];
				int pos = 0;
				if (e.flags & RTTI::CHD_MULTINH)   flags[pos++] = 'M';
				if (e.flags & RTTI::CHD_VIRTINH)   flags[pos++] = 'V';
				if (e.flags & RTTI::CHD_AMBIGUOUS) flags[pos++] = 'A';
				flags[pos++] = 0;
				cols[2] = flags;

				// Type
				LPCSTR tag = strchr(e.str, '@');
				if (tag)
				{
					char buffer[MAXSTR];
					int pos = (tag - e.str);
					if (pos > SIZESTR(buffer)) pos = SIZESTR(buffer);
					memcpy(buffer, e.str, pos);
					buffer[pos] = 0;
					cols[3] = buffer;
					++tag;
				}
				else
				{
					// Can happen when string is MAXSTR and greater
					cols[3] = "??** MAXSTR overflow!";
					tag = e.str;
				}

				// Composition/hierarchy
				cols[4] = tag;

				//*icon_ = ((e.flags & RTTI::IS_TOP_LEVEL) ? 77 : 191);
				*icon_ = 191;

				// Indicate entry is not a top/parent level by color
				if (!(e.flags & RTTI::IS_TOP_LEVEL))
					attributes->color = NOT_PARENT_COLOR;
			}
		}
		CATCH()
	}

	virtual cbres_t enter(sizevec_t *sel)
	{
		size_t n = sel->front();
		if (n < get_count())
		{
			TBLENTRY e;
			getTableEntry(e, (UINT)n);
			jumpto(e.vft);
		}
		return NOTHING_CHANGED;
	}

	virtual void closed()
	{
		freeWorkingData();
	}

private:
	#ifdef __EA64__
	char addressFormat[16];
	#endif

};

// find_widget
static QWidget *findChildByClass(QWidgetList &wl, LPCSTR className)
{
    foreach(QWidget *w, wl)
        if (strcmp(w->metaObject()->className(), className) == 0)
            return(w);
    return nullptr;
}

// Find widget by title text
// If IDs are constant can use "static QWidget *QWidget::find(WId);"?
void customizeChooseWindow()
{
    try
    {
		QApplication::processEvents();

        // Get parent chooser dock widget
        QWidgetList pl = QApplication::activeWindow()->findChildren<QWidget*>("[Class Informer]");
        if (QWidget *dw = findChildByClass(pl, "IDADockWidget"))
        {
            QFile file(STYLE_PATH "view-style.qss");
            if (file.open(QFile::ReadOnly | QFile::Text))
                dw->setStyleSheet(QTextStream(&file).readAll());
        }
        else
            msg("** customizeChooseWindow(): \"IDADockWidget\" not found!\n");

        // Get chooser widget
        if (QTableView *tv = (QTableView *) findChildByClass(pl, "TChooserView"))
        {
            // Set sort by type name
            tv->sortByColumn(3, Qt::DescendingOrder);

            // Resize to contents
            tv->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
            tv->resizeColumnsToContents();
            tv->horizontalHeader()->setSectionResizeMode(QHeaderView::Interactive);

            UINT count = getTableCount();
            for (UINT row = 0; row < count; row++)
                tv->setRowHeight(row, 24);
        }
        else
            msg("** customizeChooseWindow(): \"TChooserView\" not found!\n");
    }
    CATCH()
}


static BOOL isTempName(ea_t ear)
{
	if (hasUniqueName(ear))
	{
		qstring n = get_name(ear);
		LPCSTR nn = n.c_str();
		while (nn && (nn == strstr(nn, "j_"))) nn += 2;
		if ((nn == strstr(nn, "__ICI__")) && (nn != strstr(nn, "__ICI__TooLong")))
			return TRUE;
	}
	return FALSE;
}

static void clearDefaultName(ea_t ear)
{
	if (isTempName(ear))
		set_name(ear, "");
}

bool idaapi run(size_t arg)
{
    try
    {
        char version[16];
        sprintf_s(version, sizeof(version), "%u.%u", HIBYTE(MY_VERSION), LOBYTE(MY_VERSION));
        msg("\n>> Class Informer: v: %s, built: %s, By Sirmabus\n", version, __DATE__);
#ifdef __EA64__
		msg(">> \t x64 modified for B.S. game\n");
#else
		msg(">> \t x32 modified for B.S. game\n");
#endif

		if (netNode)
		{
			msg("* Already active. Please close the chooser window first to run it again.\n");
		    return true;
		}

		if (!initResourcesOnce)
		{
			initResourcesOnce = TRUE;
			Q_INIT_RESOURCE(ClassInformerRes);

			QFile file(STYLE_PATH "icon.png");
			if (file.open(QFile::ReadOnly))
			{
				QByteArray ba = file.readAll();
				chooserIcon = load_custom_icon(ba.constData(), ba.size(), "png");
			}
		}

        if(!auto_is_ok())
        {
            msg("** Class Informer: Must wait for IDA to finish processing before starting plug-in! **\n*** Aborted ***\n\n");
            return true;
        }

        OggPlay::endPlay();
        freeWorkingData();
        optionAudioOnDone   = TRUE;
        optionProcessStatic = TRUE;
        optionPlaceStructs  = TRUE;
        startingFuncCount   = (UINT) get_func_qty();
		colList.clear();
        staticCppCtorCnt = staticCCtorCnt = staticCtorDtorCnt = staticCDtorCnt = 0;
		missingColsFixed = vftablesFixed = 0;

        // Create storage netnode
        if(!(netNode = new netnode(NETNODE_NAME, SIZESTR(NETNODE_NAME), TRUE)))
        {
            QASSERT(66, FALSE);
            return true;
        }

		// Read existing storage if any
        UINT tableCount     = getTableCount();
        WORD storageVersion = getStoreVersion();
        BOOL storageExists  = (tableCount > 0);

        // Ask if we should use storage or process again
		if (storageExists)
		{
			// Version 2.3 didn't change the format
			UINT major = HIBYTE(storageVersion), minor = LOBYTE(storageVersion);
			if ((major != MY_VERSION_MAJOR) || (minor < MY_VERSION_MINOR))
			{
				msg("* Storage version mismatch, must rescan *\n");
				storageExists = FALSE;
			}
			else
				storageExists = (ask_yn(1, "TITLE Class Informer \nHIDECANCEL\nUse previously stored result?        ") == 1);
		}

        BOOL aborted = FALSE;
        if(!storageExists)
        {
            newNetnodeStore();

            // Only MS Visual C++ targets are supported
            comp_t cmp = get_comp(default_compiler());
            if (cmp != COMP_MS)
            {
                msg("** IDA reports target compiler: \"%s\"\n", get_compiler_name(cmp));
                int iResult = ask_buttons(NULL, NULL, NULL, 0, "TITLE Class Informer\nHIDECANCEL\nIDA reports this IDB's compiler as: \"%s\" \n\nThis plug-in only understands MS Visual C++ targets.\nRunning it on other targets (like Borland© compiled, etc.) will have unpredicted results.   \n\nDo you want to continue anyhow?", get_compiler_name(cmp));
                if (iResult != 1)
                {
                    msg("- Aborted -\n\n");
                    return true;
                }
            }

            // Do UI
			SegSelect::segments *segList = NULL;
            if (doMainDialog(optionPlaceStructs, optionProcessStatic, optionAudioOnDone, &segList, optionClean, optionFullClear))
            {
                msg("- Canceled -\n\n");
				freeWorkingData();
                return true;
            }

            msg("Working..\n");
            WaitBox::show("Class Informer", "Please wait..", "url(" STYLE_PATH "progress-style.qss)", STYLE_PATH "icon.png");
            WaitBox::updateAndCancelCheck(-1);
            s_startTime = getTimeStamp();

			// Undefine any temp name
			UINT fq = (UINT)get_func_qty();
			for (UINT index = 0; index < fq; index++)
			{
				if (0 == index % 10000)
					msgR("\t\t%35s Funcs:\t% 7d of % 7d\n", "Deleting temp functions names:", index + 1, fq);

				func_t* funcTo = getn_func(index);
				if (funcTo)
					clearDefaultName(funcTo->start_ea);
			}

			// Add structure definitions to IDA once per session
            static BOOL createStructsOnce = FALSE;
            if (optionPlaceStructs && !createStructsOnce)
            {
                createStructsOnce = TRUE;
                RTTI::addDefinitionsToIda();
            }

            if(optionProcessStatic)
            {
                // Process global and static ctor sections
                msg("\nProcessing C/C++ ctor & dtor tables..\n");
				msg("-------------------------------------------------\n");
                if (!(aborted = processStaticTables()))
                    msg("Processing time: %s.\n", timeString(getTimeStamp() - s_startTime));
            }

            if (!aborted)
            {
                // Get RTTI data
                if (!(aborted = getRttiData(segList)))
                {
                    // Optionally play completion sound
                    if (optionAudioOnDone)
                    {
                        TIMESTAMP endTime = (getTimeStamp() - s_startTime);
                        if (endTime > (TIMESTAMP) 2.4)
                        {
                            OggPlay::endPlay();
                            QFile file(STYLE_PATH "completed.ogg");
                            if (file.open(QFile::ReadOnly))
                            {
                                QByteArray ba = file.readAll();
                                OggPlay::playFromMemory((const PVOID)ba.constData(), ba.size(), TRUE);
                            }
                        }
                    }

                    showEndStats();
                    msg("Done.\n\n");
                }
            }

			WaitBox::hide();
            refresh_idaview_anyway();
            if (aborted)
            {
                msg("- Aborted -\n\n");
                return true;
            }
        }

        // Show list result window
        if (!aborted && (getTableCount() > 0))
        {
			// The chooser allocation will free it's self automatically
			rtti_chooser *chooserPtr = new rtti_chooser();
			chooserPtr->choose();

			customizeChooseWindow();
        }
    }
	CATCH()

	return true;
}

// Print out end stats
static void showEndStats()
{
    try
    {
        msg(" \n\n");
        msg("=========== Stats ===========\n");

		UINT vftableCount = getTableCount();
		if (vftablesFixed)
		msg("  RTTI vftables: %u, fixed: %u (%.1f%%)\n", vftableCount, vftablesFixed, ((double) vftablesFixed / (double) vftableCount)  * 100.0);
		else
		msg("  RTTI vftables: %u\n", vftableCount);

		// Amount of COLs fixed is usually about the same as vftables fixed, but the same COL can be used in multiple vftables
		//if(missingColsFixed)
		//msg("     COLs fixed: %u of %u (%.1f%%)\n", missingColsFixed, colCount,  ((double) missingColsFixed / (double) colCount)  * 100.0);

		UINT functionsFixed = ((UINT) get_func_qty() - startingFuncCount);
		if(functionsFixed)
        msg("Functions fixed: %u\n", functionsFixed);

        msg("Processing time: %s\n", timeString(getTimeStamp() - s_startTime));
    }
    CATCH()
}


// ================================================================================================

// Fix/create label and comment C/C++ initializer tables
static void setIntializerTable(ea_t start, ea_t end, BOOL isCpp)
{
    try
    {
        if (UINT count = ((end - start) / sizeof(ea_t)))
        {
            // Set table elements as pointers
            ea_t ea = start;
            while (ea <= end)
            {
                fixEa(ea);

                // Might fix missing/messed stubs
                if (ea_t func = get_32bit(ea))
                    fixFunction(func);

                ea += sizeof(ea_t);
            };

            // Start label
            if (!hasUniqueName(start))
            {
                char name[MAXSTR];
                if (isCpp)
                    sprintf_s(name, sizeof(name), "__xc_a_%d", staticCppCtorCnt);
                else
                    sprintf_s(name, sizeof(name), "__xi_a_%d", staticCCtorCnt);
                setName(start, name);
            }

			size_t index = 0;
			for (ea_t ea = start; ea < end; ea += sizeof(ea_t))
			{
				ea_t ear;
				if (getVerify_t(ea, ear))
				{
					// Missing/bad code?
					if (get_func(ear))
					{
						clearDefaultName(ear);
						if (!hasUniqueName(ear))
						{
							char name[MAXSTR]; name[SIZESTR(name)] = 0;
							if (isCpp)
								_snprintf(name, SIZESTR(name), "__ICI__%s_%d_%0.5d", "StaticCppCtor", staticCppCtorCnt, index);
							else
								_snprintf(name, SIZESTR(name), "__ICI__%s_%d_%0.5d", "StaticCCtor", staticCCtorCnt, index);
							set_name(ear, name, (SN_NON_AUTO | SN_NOWARN));
						}
					}
				}
				index++;
			}

            // End label
            if (!hasUniqueName(end))
            {
                char name[MAXSTR];
                if (isCpp)
                    sprintf_s(name, sizeof(name), "__xc_z_%d", staticCppCtorCnt);
                else
                    sprintf_s(name, sizeof(name), "__xi_z_%d", staticCCtorCnt);
                setName(end, name);
            }

            // Comment
            // Never overwrite, it might be the segment comment
            if (!hasAnteriorComment(start))
            {
                if (isCpp)
					setAnteriorComment(start, "%d C++ static ctors (#classinformer)", count);
                else
					setAnteriorComment(start, "%d C initializers (#classinformer)", count);
            }
            else
            // Place comment @ address instead
            if (!hasComment(start))
            {
                if (isCpp)
                {
					char comment[MAXSTR];
                    sprintf_s(comment, sizeof(comment), "%d C++ static ctors (#classinformer)", count);
                    setComment(start, comment, TRUE);
                }
                else
                {
					char comment[MAXSTR];
                    sprintf_s(comment, sizeof(comment), "%d C initializers (#classinformer)", count);
                    setComment(start, comment, TRUE);
                }
            }

            if (isCpp)
                staticCppCtorCnt++;
            else
                staticCCtorCnt++;
        }
    }
    CATCH()
}

// Fix/create label and comment C/C++ terminator tables
static void setTerminatorTable(ea_t start, ea_t end)
{
    try
    {
        if (UINT count = ((end - start) / sizeof(ea_t)))
        {
            // Set table elements as pointers
            ea_t ea = start;
            while (ea <= end)
            {
                fixEa(ea);

                // Fix function
                if (ea_t func = getEa(ea))
                    fixFunction(func);

                ea += sizeof(ea_t);
            };

            // Start label
            if (!hasUniqueName(start))
            {
                char name[MAXSTR];
                _snprintf_s(name, sizeof(name), SIZESTR(name), "__xt_a_%d", staticCDtorCnt);
                setName(start, name);
            }

			size_t index = 0;
			for (ea_t ea = start; ea < end; ea += sizeof(ea_t))
			{
				ea_t ear;
				if (getVerify_t(ea, ear))
				{
					// Missing/bad code?
					if (get_func(ear))
					{
						clearDefaultName(ear);
						if (!hasUniqueName(ear))
						{
							char name[MAXSTR]; name[SIZESTR(name)] = 0;
							_snprintf(name, SIZESTR(name), "__ICI__%s_%d_%0.5d", "StaticCDtor", staticCDtorCnt, index);
							set_name(ear, name, (SN_NON_AUTO | SN_NOWARN));
						}
					}
				}
				index++;
			}

            // End label
            if (!hasUniqueName(end))
            {
				char name[MAXSTR];
                _snprintf_s(name, sizeof(name), SIZESTR(name), "__xt_z_%d", staticCDtorCnt);
                setName(end, name);
            }

            // Comment
            // Never overwrite, it might be the segment comment
            if (!hasAnteriorComment(start))
				setAnteriorComment(start, "%d C terminators (#classinformer)", count);
            else
            // Place comment @ address instead
            if (!hasComment(start))
            {
                char comment[MAXSTR];
                _snprintf_s(comment, sizeof(comment), SIZESTR(comment), "%d C terminators (#classinformer)", count);
                setComment(start, comment, TRUE);
            }

            staticCDtorCnt++;
        }
    }
    CATCH()
}

// "" for when we are uncertain of ctor or dtor type table
static void setCtorDtorTable(ea_t start, ea_t end)
{
    try
    {
        if (UINT count = ((end - start) / sizeof(ea_t)))
        {
            // Set table elements as pointers
            ea_t ea = start;
            while (ea <= end)
            {
                fixEa(ea);

                // Fix function
                if (ea_t func = getEa(ea))
                    fixFunction(func);

                ea += sizeof(ea_t);
            };

            // Start label
            if (!hasUniqueName(start))
            {
                char name[MAXSTR];
                _snprintf_s(name, sizeof(name), SIZESTR(name), "__x?_a_%d", staticCtorDtorCnt);
                setName(start, name);
            }

			size_t index = 0;
			for (ea_t ea = start; ea < end; ea += sizeof(ea_t))
			{
				ea_t ear;
				if (getVerify_t(ea, ear))
				{
					// Missing/bad code?
					if (get_func(ear))
					{
						clearDefaultName(ear);
						if (!hasUniqueName(ear))
						{
							char name[MAXSTR]; name[SIZESTR(name)] = 0;
							_snprintf(name, SIZESTR(name), "__ICI__%s_%d_%0.5d", "StaticCtorDtor", staticCDtorCnt, index);
							set_name(ear, name, (SN_NON_AUTO | SN_NOWARN));
						}
					}
				}
				index++;
			}

            // End label
            if (!hasUniqueName(end))
            {
                char name[MAXSTR];
                _snprintf_s(name, sizeof(name), SIZESTR(name), "__x?_z_%d", staticCtorDtorCnt);
                setName(end, name);
            }

            // Comment
            // Never overwrite, it might be the segment comment
            if (!hasAnteriorComment(start))
				setAnteriorComment(start, "%d C initializers/terminators (#classinformer)", count);
            else
            // Place comment @ address instead
            if (!hasComment(start))
            {
                char comment[MAXSTR];
                _snprintf_s(comment, sizeof(comment), SIZESTR(comment), "%d C initializers/terminators (#classinformer)", count);
                setComment(start, comment, TRUE);
            }

            staticCtorDtorCnt++;
        }
    }
    CATCH()
}


// Process redister based _initterm()
static void processRegisterInitterm(ea_t start, ea_t end, ea_t call)
{
    if ((end != BADADDR) && (start != BADADDR))
    {
        // Should be in the same segment
        if (getseg(start) == getseg(end))
        {
            if (start > end)
                swap_t(start, end);

            msg("    " EAFORMAT " to " EAFORMAT " CTOR table.\n", start, end);
            setIntializerTable(start, end, TRUE);
			if(!hasComment(call))
				setComment(call, "_initterm", TRUE);
        }
        else
            msg("  ** Bad address range of " EAFORMAT ", " EAFORMAT " for \"_initterm\" type ** <click address>.\n", start, end);
    }
}

static UINT doInittermTable(func_t *func, ea_t start, ea_t end, LPCTSTR name)
{
    UINT found = FALSE;

    if ((start != BADADDR) && (end != BADADDR))
    {
        // Should be in the same segment
        if (getseg(start) == getseg(end))
        {
            if (start > end)
                swap_t(start, end);

            // Try to determine if we are in dtor or ctor section
            if (func)
            {
                qstring qstr;
                if (get_long_name(&qstr, func->start_ea) > 0)
                {
					char funcName[MAXSTR];
                    strncpy_s(funcName, MAXSTR, qstr.c_str(), (MAXSTR - 1));
                    _strlwr(funcName);

                    // Start/ctor?
                    if (strstr(funcName, "cinit") || strstr(funcName, "tmaincrtstartup") || strstr(funcName, "start"))
                    {
                        msg("    " EAFORMAT " to " EAFORMAT " CTOR table.\n", start, end);
                        setIntializerTable(start, end, TRUE);
                        found = TRUE;
                    }
                    else
                    // Exit/dtor function?
                    if (strstr(funcName, "exit"))
                    {
                        msg("    " EAFORMAT " to " EAFORMAT " DTOR table.\n", start, end);
                        setTerminatorTable(start, end);
                        found = TRUE;
                    }
                }
            }

            if (!found)
            {
                // Fall back to generic assumption
                msg("    " EAFORMAT " to " EAFORMAT " CTOR/DTOR table.\n", start, end);
                setCtorDtorTable(start, end);
                found = TRUE;
            }
        }
        else
            msg("    ** Miss matched segment table addresses " EAFORMAT ", " EAFORMAT " for \"%s\" type **\n", start, end, name);
    }
    else
        msg("    ** Bad input address range of " EAFORMAT ", " EAFORMAT " for \"%s\" type **\n", start, end, name);

    return(found);
}

// Process _initterm function
// Returns TRUE if at least one found
static BOOL processInitterm(ea_t address, LPCTSTR name)
{
    msg(EAFORMAT" processInitterm: \"%s\" \n", address, name);
    UINT count = 0;

    // Walk xrefs
    ea_t xref = get_first_fcref_to(address);
    while (xref && (xref != BADADDR))
    {
        msg("  " EAFORMAT " \"%s\" xref.\n", xref, name);

        // Should be code
        if (is_code(get_flags(xref)))
        {
            do
            {
                // The most common are two instruction arguments
                // Back up two instructions
                ea_t instruction1 = prev_head(xref, 0);
                if (instruction1 == BADADDR)
                    break;
                ea_t instruction2 = prev_head(instruction1, 0);
                if (instruction2 == BADADDR)
                    break;

                // Bail instructions are past the function start now
                func_t *func = get_func(xref);
                if (func && (instruction2 < func->start_ea))
                {
                    //msg("   " EAFORMAT " arg2 outside of contained function **\n", func->start_ea);
                    break;
                }

                struct ARG2PAT
                {
                    LPCSTR pattern;
                    UINT start, end, padding;
                } static const ALIGN(16) arg2pat[] =
                {
                    #ifndef __EA64__
                    { "68 ?? ?? ?? ?? 68", 6, 1 },          // push offset s, push offset e
                    { "B8 ?? ?? ?? ?? C7 04 24", 8, 1 },    // mov [esp+4+var_4], offset s, mov eax, offset e   Maestia
                    { "68 ?? ?? ?? ?? B8", 6, 1 },          // mov eax, offset s, push offset e
                    #else
                    { "48 8D 15 ?? ?? ?? ?? 48 8D 0D", 3, 3 },  // lea rdx,s, lea rcx,e
                    #endif
                };
                BOOL matched = FALSE;
                for (UINT i = 0; (i < qnumber(arg2pat)) && !matched; i++)
                {
					ea_t match = FIND_BINARY(instruction2, xref, arg2pat[i].pattern);
					if (match != BADADDR)
					{
						#ifndef __EA64__
						ea_t start = getEa(match + arg2pat[i].start);
						ea_t end   = getEa(match + arg2pat[i].end);
						#else
						UINT startOffset = get_32bit(instruction1 + arg2pat[i].start);
						UINT endOffset   = get_32bit(instruction2 + arg2pat[i].end);
						ea_t start = (instruction1 + 7 + *((PINT) &startOffset)); // TODO: 7 is hard coded instruction length, put this in arg2pat table?
						ea_t end   = (instruction2 + 7 + *((PINT) &endOffset));
						#endif
						msg("  " EAFORMAT " Two instruction pattern match #%d\n", match, i);
						count += doInittermTable(func, start, end, name);
						matched = TRUE;
						break;
					}
                }

                // 3 instruction
                /*
                searchStart = prev_head(searchStart, BADADDR);
                if (searchStart == BADADDR)
                    break;
                if (func && (searchStart < func->start_ea))
                    break;

                    if (func && (searchStart < func->start_ea))
                    {
                        msg("  " EAFORMAT " arg3 outside of contained function **\n", func->start_ea);
                        break;
                    }

                .text:10008F78                 push    offset unk_1000B1B8
                .text:10008F7D                 push    offset unk_1000B1B0
                .text:10008F82                 mov     dword_1000F83C, 1
                "68 ?? ?? ?? ?? 68 ?? ?? ?? ?? C7 05 ?? ?? ?? ?? ?? ?? ?? ??"
                */

                if (!matched)
                    msg("  ** arguments not located!\n");

            } while (FALSE);
        }
        else
            msg("  " EAFORMAT " ** \"%s\" xref is not code! **\n", xref, name);

        xref = get_next_fcref_to(address, xref);
    };

    msg(" \n");
    return(count > 0);
}


// Process global/static ctor & dtor tables.
// Returns TRUE if user aborted
static BOOL processStaticTables()
{
    staticCppCtorCnt = staticCCtorCnt = staticCtorDtorCnt = staticCDtorCnt = 0;

    // x64 __tmainCRTStartup, _CRT_INIT

    try
    {
        // Locate _initterm() and _initterm_e() functions
        STRMAP inittermMap;
        func_t  *cinitFunc = NULL;
        UINT funcCount = (UINT) get_func_qty();

        for (UINT i = 0; i < funcCount; i++)
        {
            if (func_t *func = getn_func(i))
            {
                qstring qstr;
                if (get_long_name(&qstr, func->start_ea) > 0)
				{
                    char name[MAXSTR];
                    strncpy_s(name, MAXSTR, qstr.c_str(), (MAXSTR - 1));

                    int len = (int) strlen(name);
                    if (len >= SIZESTR("_cinit"))
                    {
                        if (strcmp((name + (len - SIZESTR("_cinit"))), "_cinit") == 0)
                        {
                            // Skip stub functions
                            if (func->size() > 16)
                            {
                                msg(EAFORMAT" C: \"%s\", %d bytes.\n", func->start_ea, name, func->size());
                                _ASSERT(cinitFunc == NULL);
                                cinitFunc = func;
                            }
                        }
                        else
                        if ((len >= SIZESTR("_initterm")) && (strcmp((name + (len - SIZESTR("_initterm"))), "_initterm") == 0))
                        {
                            msg(EAFORMAT" I: \"%s\", %d bytes.\n", func->start_ea, name, func->size());
                            inittermMap[func->start_ea] = name;
                        }
                        else
                        if ((len >= SIZESTR("_initterm_e")) && (strcmp((name + (len - SIZESTR("_initterm_e"))), "_initterm_e") == 0))
                        {
                            msg(EAFORMAT" E: \"%s\", %d bytes.\n", func->start_ea, name, func->size());
                            inittermMap[func->start_ea] = name;
                        }
                    }
                }
            }
        }

		if(WaitBox::isUpdateTime())
			if (WaitBox::updateAndCancelCheck())
				return(TRUE);

        // Look for import versions
        {
            static LPCSTR imports[] =
            {
                "__imp__initterm", "__imp__initterm_e"
            };
            for (UINT i = 0; i < qnumber(imports); i++)
            {
                ea_t adress = get_name_ea(BADADDR, imports[i]);
                if (adress != BADADDR)
                {
                    if (inittermMap.find(adress) == inittermMap.end())
                    {
                        msg(EAFORMAT" import: \"%s\".\n", adress, imports[i]);
                        inittermMap[adress] = imports[i];
                    }
                }
            }
        }

        // Process register based _initterm() calls inside _cint()
        if (cinitFunc)
        {
            struct CREPAT
            {
                LPCSTR pattern;
                UINT start, end, call;
            } static const ALIGN(16) pat[] =
            {
                { "B8 ?? ?? ?? ?? BE ?? ?? ?? ?? 59 8B F8 3B C6 73 0F 8B 07 85 C0 74 02 FF D0 83 C7 04 3B FE 72 F1", 1, 6, 0x17},
                { "BE ?? ?? ?? ?? 8B C6 BF ?? ?? ?? ?? 3B C7 59 73 0F 8B 06 85 C0 74 02 FF D0 83 C6 04 3B F7 72 F1", 1, 8, 0x17},
            };

            for (UINT i = 0; i < qnumber(pat); i++)
            {
				ea_t match = FIND_BINARY(cinitFunc->start_ea, cinitFunc->end_ea, pat[i].pattern);
                while (match != BADADDR)
                {
                    msg("  " EAFORMAT " Register _initterm(), pattern #%d.\n", match, i);
                    ea_t start = getEa(match + pat[i].start);
                    ea_t end   = getEa(match + pat[i].end);
                    processRegisterInitterm(start, end, (match + pat[i].call));
					match = FIND_BINARY(match + 30, cinitFunc->end_ea, pat[i].pattern);
                };
            }
        }

        msg(" \n");
		if (WaitBox::isUpdateTime())
			if (WaitBox::updateAndCancelCheck())
				return(TRUE);

        // Process _initterm references
        for (STRMAP::iterator it = inittermMap.begin(); it != inittermMap.end(); ++it)
        {
            if (processInitterm(it->first, it->second.c_str()))
				if (WaitBox::isUpdateTime())
					if (WaitBox::updateAndCancelCheck())
						return(TRUE);
        }

		if (WaitBox::isUpdateTime())
			if (WaitBox::updateAndCancelCheck())
				return(TRUE);
    }
    CATCH()

    return(FALSE);
}

// ================================================================================================


// Return TRUE if address as a anterior comment
inline BOOL hasAnteriorComment(ea_t ea)
{
    return(get_first_free_extra_cmtidx(ea, E_PREV) != E_PREV);
}

// Delete any anterior comment(s) at address if there is some
inline void killAnteriorComments(ea_t ea)
{
    delete_extra_cmts(ea, E_PREV);
}

// Force a memory location to be DWORD size
void fixDword(ea_t ea)
{
    if (!is_dword(get_flags(ea)))
    {
        setUnknown(ea, sizeof(DWORD));
        create_dword(ea, sizeof(DWORD));
    }
}

// Force memory location to be ea_t size
void fixEa(ea_t ea)
{
    #ifndef __EA64__
    if (!is_dword(get_flags(ea)))
    #else
    if (!is_qword(get_flags(ea)))
    #endif
    {
        setUnknown(ea, sizeof(ea_t));
        #ifndef __EA64__
        create_dword(ea, sizeof(ea_t));
        #else
		create_qword(ea, sizeof(ea_t));
        #endif
    }
}

// Address should be a code function
bool fixFunction(ea_t ea)
{
    flags_t flags = get_flags(ea);

	// No code here?
    if (!is_code(flags))
    {
		// Attempt to make it so
        create_insn(ea);
		if (!is_code(flags))
			return FALSE;
		else
			add_func(ea, BADADDR);
	}
    else
	// Yea there is code here, should have a function boddy too
    if (!is_func(flags))
        add_func(ea, BADADDR);
	return TRUE;
}

// Get IDA EA bit value with verification
BOOL getVerifyEa(ea_t ea, ea_t &rValue)
{
    // Location valid?
    if (is_loaded(ea))
    {
        // Get ea_t value
        rValue = getEa(ea);
        return(TRUE);
    }

    return(FALSE);
}


// Undecorate to minimal class name
// typeid(T).name()
// http://en.wikipedia.org/wiki/Name_mangling
// http://en.wikipedia.org/wiki/Visual_C%2B%2B_name_mangling
// http://www.agner.org/optimize/calling_conventions.pdf

BOOL getPlainTypeName(__in LPCSTR mangled, __out_bcount(MAXSTR) LPSTR outStr)
{
    outStr[0] = outStr[MAXSTR - 1] = 0;

    // Use CRT function for type names
    if (mangled[0] == '.')
    {
        __unDName(outStr, mangled + 1, MAXSTR, mallocWrap, free, (UNDNAME_32_BIT_DECODE | UNDNAME_TYPE_ONLY | UNDNAME_NO_ECSU));
        if ((outStr[0] == 0) || (strcmp((mangled + 1), outStr) == 0))
        {
            msg("** getPlainClassName:__unDName() failed to unmangle! input: \"%s\"\n", mangled);
            return(FALSE);
        }
    }
    else
    // IDA demangler for everything else
    {
        qstring qstr;
        int result = demangle_name(&qstr, mangled, M_COMPILER /*MT_MSCOMP*/, DQT_FULL);
        if (result < 0)
        {
            //msg("** getPlainClassName:demangle_name2() failed to unmangle! result: %d, input: \"%s\"\n", result, mangled);
            return(FALSE);
        }

        // No inhibit flags will drop this
        strncpy_s(outStr, MAXSTR, qstr.c_str(), (MAXSTR - 1));
        if (LPSTR ending = strstr(outStr, "::`vftable'"))
            *ending = 0;
    }

    return(TRUE);
}

// Wrapper for 'add_struc_member()' with error messages
// See to make more sense of types: http://idapython.googlecode.com/svn-history/r116/trunk/python/idc.py
int addStrucMember(struc_t *sptr, char *name, ea_t offset, flags_t flag, opinfo_t *type, asize_t nbytes)
{
    int r = add_struc_member(sptr, name, offset, flag, type, nbytes);
    switch(r)
    {
        case STRUC_ERROR_MEMBER_NAME:
        msg("AddStrucMember(): error: already has member with this name (bad name)\n");
        break;

        case STRUC_ERROR_MEMBER_OFFSET:
        msg("AddStrucMember(): error: already has member at this offset\n");
        break;

        case STRUC_ERROR_MEMBER_SIZE:
        msg("AddStrucMember(): error: bad number of bytes or bad sizeof(type)\n");
        break;

        case STRUC_ERROR_MEMBER_TINFO:
        msg("AddStrucMember(): error: bad typeid parameter\n");
        break;

        case STRUC_ERROR_MEMBER_STRUCT:
        msg("AddStrucMember(): error: bad struct id (the 1st argument)\n");
        break;

        case STRUC_ERROR_MEMBER_UNIVAR:
        msg("AddStrucMember(): error: unions can't have variable sized members\n");
        break;

        case STRUC_ERROR_MEMBER_VARLAST:
        msg("AddStrucMember(): error: variable sized member should be the last member in the structure\n");
        break;

        case STRUC_ERROR_MEMBER_NESTED:
        msg("AddStrucMember(): error: recursive structure nesting is forbidden\n");
        break;
    };

    return(r);
}


void setUnknown(ea_t ea, int size)
{
	del_items(ea, DELIT_EXPAND, size);

#if 0
    // TODO: Does the item overrun problem still exist in IDA 7?
    //del_items_range(ea, (size_t)size, DOUNK_SIMPLE);
    while (size > 0)
    {
        int isize = get_item_size(ea);
        if (isize > size)
            break;
        else
        {
            do_unknown(ea, DOUNK_SIMPLE);
            ea += (ea_t)isize, size -= isize;
        }
    };
#endif
}

// Set name for address
void setName(ea_t ea, __in LPCSTR name)
{
	//msg("%08X \"%s\"\n", ea, name);
	set_name(ea, name, (SN_NON_AUTO | SN_NOWARN | SN_NOCHECK | SN_FORCE));
}

// Set comment at address
void setComment(ea_t ea, LPCSTR comment, BOOL rptble)
{
	//msg("%08X cmt: \"%s\"\n", ea, comment);
	set_cmt(ea, comment, rptble);
}

// Set comment at the line above the address
void setAnteriorComment(ea_t ea, const char *format, ...)
{
	va_list va;
	va_start(va, format);
	vadd_extra_line(ea, 0, format, va);
	va_end(va);
}


// Scan segment for COLs
static BOOL scanSeg4Cols(segment_t *seg)
{
	qstring name;
    if (get_segm_name(&name, seg) <= 0)
		name = "???";
    msg(" N: \"%s\", A: " EAFORMAT " - " EAFORMAT ", S: %s.\n", name.c_str(), seg->start_ea, seg->end_ea, byteSizeString(seg->size()));

    UINT found = 0;
    if (seg->size() >= sizeof(RTTI::_RTTICompleteObjectLocator))
    {
        ea_t startEA = ((seg->start_ea + sizeof(UINT)) & ~((ea_t) (sizeof(UINT) - 1)));
        ea_t endEA   = (seg->end_ea - sizeof(RTTI::_RTTICompleteObjectLocator));

        for (ea_t ptr = startEA; ptr < endEA;)
        {
            #ifdef __EA64__
            // Check for possible COL here
            // Signature will be one
            // TODO: Is this always 1 or can it be zero like 32bit?
            if (get_32bit(ptr + offsetof(RTTI::_RTTICompleteObjectLocator, signature)) == 1)
            {
                if (RTTI::_RTTICompleteObjectLocator::isValid(ptr))
                {
                    // yes
                    colList.push_front(ptr);
					missingColsFixed += (UINT) RTTI::_RTTICompleteObjectLocator::tryStruct(ptr);
                    ptr += sizeof(RTTI::_RTTICompleteObjectLocator);
					found++;
                    continue;
                }
            }
            else
            {
                // TODO: Should we check stray BCDs?
                // Each value would have to be tested for a valid type_def and
                // the pattern is pretty ambiguous.
            }
            #else
            // TypeDescriptor address here?
            ea_t ea = getEa(ptr);
            if (ea >= 0x10000)
            {
                if (RTTI::type_info::isValid(ea))
                {
                    // yes, a COL here?
                    ea_t col = (ptr - offsetof(RTTI::_RTTICompleteObjectLocator, typeDescriptor));
                    if (RTTI::_RTTICompleteObjectLocator::isValid2(col))
                    {
                        // yes
                        colList.push_front(col);
						missingColsFixed += (UINT) RTTI::_RTTICompleteObjectLocator::tryStruct(col);
                        ptr += sizeof(RTTI::_RTTICompleteObjectLocator);
						found++;
                        continue;
                    }
                    /*
                    else
                    // No, is it a BCD then?
                    if (RTTI::_RTTIBaseClassDescriptor::isValid2(ptr))
                    {
                        // yes
                        char dontCare[MAXSTR];
                        RTTI::_RTTIBaseClassDescriptor::doStruct(ptr, dontCare);
                    }
                    */
                }
            }
            #endif

            if (WaitBox::isUpdateTime())
                if (WaitBox::updateAndCancelCheck())
                    return(TRUE);

            ptr += sizeof(UINT);
        }
    }

    if (found)
    {
        char numBuffer[32];
        msg(" Count: %s\n", prettyNumberString(found, numBuffer));
    }
    return(FALSE);
}
//
// Locate COL by descriptor list
static BOOL findCols(SegSelect::segments *segList)
{
    try
    {
        TIMESTAMP startTime = getTimeStamp();

		// Use user selected segments
		if (segList && !segList->empty())
		{
			for (SegSelect::segments::iterator it = segList->begin(); it != segList->end(); ++it)
			{
				if (scanSeg4Cols(*it))
					return(FALSE);
			}
		}
		else
		// Scan data segments named
		{
			int segCount = get_segm_qty();
			for (int i = 0; i < segCount; i++)
			{
				if (segment_t *seg = getnseg(i))
				{
					if (seg->type == SEG_DATA)
					{
						if (scanSeg4Cols(seg))
							return(FALSE);
					}
				}
			}
		}

        char numBuffer[32];
        msg("     Total COL: %s\n", prettyNumberString(colList.size(), numBuffer));
        msg("COL scan time: %.3f\n", (getTimeStamp() - startTime));
    }
    CATCH()
    return(FALSE);
}


// Locate vftables
static BOOL scanSeg4Vftables(segment_t *seg, eaRefMap &colMap)
{
	qstring name;
	if (get_segm_name(&name, seg) <= 0)
		name = "???";
	msg(" N: \"%s\", A: " EAFORMAT " - " EAFORMAT ", S: %s.\n", name.c_str(), seg->start_ea, seg->end_ea, byteSizeString(seg->size()));

    UINT foundCount = 0;
    if (seg->size() >= sizeof(ea_t))
    {
        ea_t startEA = ((seg->start_ea + sizeof(ea_t)) & ~((ea_t) (sizeof(ea_t) - 1)));
        ea_t endEA   = (seg->end_ea - sizeof(ea_t));
		_ASSERT(((startEA | endEA) & 3) == 0);
        eaRefMap::iterator colEnd = colMap.end();

		// Walk uint32 at the time, at align 4 (same for either 32bit or 64bit targets)
        for (ea_t ptr = startEA; ptr < endEA; ptr += sizeof(UINT))
        {
            // A COL here?
            ea_t ea = getEa(ptr);
            eaRefMap::iterator it = colMap.find(ea);
            if (it != colEnd)
            {
                // yes, look for vftable one ea_t below
                ea_t vfptr  = (ptr + sizeof(ea_t));
                ea_t method = getEa(vfptr);

                // Points to code?
                if (segment_t *s = getseg(method))
                {
                    // yes,
                    if (s->type == SEG_CODE)
                    {
						BOOL result =  RTTI::processVftablePart1(vfptr, it->first);
						//if(result)
						//	msg(EAFORMAT " vft fix **\n", vfptr);
						vftablesFixed += (UINT) result;
                        it->second++, foundCount++;
                    }
                }
            }

            if (WaitBox::isUpdateTime())
                if (WaitBox::updateAndCancelCheck())
                    return(TRUE);

		}
		if (foundCount)
		{
			msgR(" N: \"%s\", A: " EAFORMAT "-" EAFORMAT ", S: %s. Pass 2\n", name.c_str(), startEA, endEA, byteSizeString(seg->size()));
			for (UINT i = 0; i < RTTI::classList.size(); i++)
				RTTI::classList[i].m_done = false;
			for (ea_t ptr = startEA; ptr < endEA; ptr += sizeof(UINT))  //sizeof(ea_t)
			{
				// COL here?
				ea_t ea = getEa(ptr);
				eaRefMap::iterator it = colMap.find(ea);
				if (it != colEnd)
				{
					// yes, look for vftable one ea_t below
					ea_t vfptr = (ptr + sizeof(ea_t));
					ea_t method = getEa(vfptr);
					// Points to code?
					if (segment_t *s = getseg(method))
					{
						// yes,
						if (s->type == SEG_CODE)
							RTTI::processVftablePart2(vfptr, it->first);
					}
				}

				if (WaitBox::isUpdateTime())
					if (WaitBox::updateAndCancelCheck())
						return(TRUE);
			}
		}
	}

    if (foundCount)
    {
		char numBuffer[32];
		msg(" Count: %s\n", prettyNumberString(foundCount, numBuffer));
	}
    return(FALSE);
}
//

LPCSTR Database = get_path(PATH_TYPE_IDB);
char DatabaseName[MAXSTR] = "";

FILE* safeOpen(LPCSTR fileName)
{
	try
	{
		FILE* f;
		return f = qfopen(fileName, "w");
	}
	catch (...)
	{
		return NULL;
	}
}

struct FileInfo
{
	FILE*	m_file;
	qstring	m_fileName;
	FileInfo(LPCSTR fileName) {
		m_file = NULL;
		m_fileName = qstring(fileName);
	}
};
typedef qvector<FileInfo> FileList;
FileList fileList;

void CloseFiles(void)
{
	for (UINT i = 0; i < fileList.size(); i++)
		if (fileList[i].m_file)
			try
		{
			qfclose(fileList[i].m_file);
			fileList[i].m_file = NULL;
		}
	catch (...)
	{
		msgR("** Exception in %s()! ***\t\tFailed to close file %d '%s'\n", __FUNCTION__, i, fileList[i].m_fileName.c_str());
	};
}

bool OpenFiles(void)
{
	fileList.push_back(FileInfo("classList.csv"));
	fileList.push_back(FileInfo("classHierarchy.csv"));
	fileList.push_back(FileInfo("classMembers.csv"));
	fileList.push_back(FileInfo("classRTTI.inc"));
	fileList.push_back(FileInfo("classInformer.hpp"));
	fileList.push_back(FileInfo("classInformer.h"));
	fileList.push_back(FileInfo("classInformer.inc"));
	fileList.push_back(FileInfo("classInformer.txt"));
	fileList.push_back(FileInfo("classRTTI.inl"));
	fileList.push_back(FileInfo("classInformer.idc"));

	strcpy_s(DatabaseName, strrchr(Database, '\\'));
	LPSTR e = strrchr(DatabaseName, '.');
	if (e) *e = 0;

	try
	{
		for (UINT i = 0; i < fileList.size(); i++)
		{
			qstring fullFileName = qstring(Database);
			UINT l = (UINT)(fullFileName.length() - strlen(".idb"));
			if ((fullFileName.substr(l) == ".idb") || (fullFileName.substr(l) == ".i64"))
				fullFileName = fullFileName.substr(0, l);
			try { qmkdir(fullFileName.c_str(), 0); }
			catch (...) {};

			fullFileName += "\\";
			fullFileName += fileList[i].m_fileName;
			//msgR("  ** %d ** Database='%s' File='%s' FullFileName='%s' ** \n", i, Database, fileList[i].m_fileName.c_str(), fullFileName.c_str());
			if (!(fileList[i].m_file = safeOpen(fullFileName.c_str())))
			{
				CloseFiles();
				return false;
			}
		}
		return true;
	}
	catch (...)
	{
		CloseFiles();
		return false;
	}
}

#define fClass			fileList[0].m_file
#define fClassHierarchy	fileList[1].m_file
#define fClassMembers	fileList[2].m_file
#define fClassRTTI		fileList[3].m_file
#define fClassIncHpp	fileList[4].m_file
#define fClassIncH		fileList[5].m_file
#define fClassInc		fileList[6].m_file
#define fClassIncTemp	fileList[7].m_file
#define fClassRTTIinl	fileList[8].m_file
#define fClassIdc		fileList[9].m_file

bool lookupVftInClassList(LPCSTR demangledColName, ea_t* parentvft, UINT* parentCount, UINT* parentIndex) {
	for (UINT i = 0; i < RTTI::classList.size(); i++) {
		//msgR("\t\t\t\tThis name:%s\t%d\n", RTTI::classList[i].m_classname, RTTI::classList[i].m_done);
		if (0 == stricmp(RTTI::classList[i].m_className, demangledColName)) {
			if (!RTTI::classList[i].m_done) {
				while (RTTI::vfTableList.size() < (i + 1))
				{
					RTTI::vfTableList.push_back();
				};

				if (!(*parentIndex == UINT(-1)))
					RTTI::vfTableList[i] = RTTI::vfTableList[*parentIndex];
				vftable::processMembers(RTTI::classList[i].m_colName, RTTI::classList[i].m_start, &RTTI::classList[i].m_end, RTTI::classList[i].m_cTypeName,
					*parentvft, *parentCount, &RTTI::vfTableList[i]);
				RTTI::classList[i].m_done = true;
				//msgR("***** Done %s\n", RTTI::classList[i].m_cTypeName);
			}
			*parentvft = RTTI::classList[i].m_vft;
			*parentCount = (RTTI::classList[i].m_end - RTTI::classList[i].m_start) / sizeof(ea_t);
			*parentIndex = i;
			return true;
		}
	}
	return false;
}

static BOOL findVftables(SegSelect::segments *segList)
{
    try
    {
        TIMESTAMP startTime = getTimeStamp();

        // COLs in a hash map for speed, plus add match counts
        eaRefMap colMap;
        for (eaList::const_iterator it = colList.begin(), end = colList.end(); it != end; ++it)
            colMap[*it] = 0;

		// Use user selected segments
		if (segList && !segList->empty())
		{
			for (SegSelect::segments::iterator it = segList->begin(); it != segList->end(); ++it)
			{
				if (scanSeg4Vftables(*it, colMap))
					return(FALSE);
			}
		}
		else
		// Scan data segments named
		{
			int segCount = get_segm_qty();
			for (int i = 0; i < segCount; i++)
			{
				if (segment_t *seg = getnseg(i))
				{
					if (seg->type == SEG_DATA)
					{
						if (scanSeg4Vftables(seg, colMap))
							return(FALSE);
					}
				}
			}
		}

        // Rebuild 'colList' with any that were not located
        if (!colList.empty())
        {
			colCount = (UINT) colList.size();
            colList.clear();

            for (eaRefMap::const_iterator it = colMap.begin(), end = colMap.end(); it != end; ++it)
            {
                if (it->second == 0)
                    colList.push_front(it->first);
            }

			//msg("\n** COLs not located: %u\n", (UINT)colList.size()); refreshUI();
        }

		for (UINT i = 0; i < RTTI::classList.size(); i++)
			RTTI::classList[i].m_done = false;
		for (UINT i = 0; i < RTTI::classList.size(); i++)
		{
			RTTI::classInfo* ci = &RTTI::classList[i];
			if (!ci->m_done)
			{
				if (0 == i % 100)
					msgR("\t\tProcessing members in Classes:\t% 7d of % 7d\n", i + 1, RTTI::classList.size());
				//msgR("\t\tClass:\t%s\tvft:%08X\tcol:%08X\tCount:%d\tBaseClassIndex:%d\tnumBaseClasses:%d\n", ci->m_className, ci->m_vft, ci->m_col, 
				//		ci->m_bcdlist.size(), ci->m_baseClassIndex, ci->m_numBaseClasses);
				ea_t parentvft = BADADDR;
				UINT parentCount = 0;
				UINT parentIndex = UINT(-1);
				for (UINT j = ci->m_numBaseClasses - 1; j > 0; j--) {
					UINT k = j + ci->m_baseClassIndex;
					if (k < ci->m_bcdlist.size())
					{
						//msgR("\t\t\t%d %d %d\n", i, j, k);
						char demangledColName[MAXSTR];
						getPlainTypeName(ci->m_bcdlist[k].m_name, demangledColName);
						//msgR("\t\t\t%d %d %d\tparent:%s\tClass name:%s\n", i, j, k, ci->m_bcdlist[k].m_name, demangledColName);
						lookupVftInClassList(demangledColName, &parentvft, &parentCount, &parentIndex);
					}
				}
				if (LPSTR compound = strstr(ci->m_className, "::")) {
					//msgR("\t\t\t\tCompound name:%s\n", compound);
					lookupVftInClassList(compound + 2, &parentvft, &parentCount, &parentIndex);
				}
				while (RTTI::vfTableList.size() < (i + 1))
				{
					RTTI::vfTableList.push_back();
				};
				if (!(parentIndex == UINT(-1)))
					RTTI::vfTableList[i] = RTTI::vfTableList[parentIndex];
				vftable::processMembers(ci->m_colName, ci->m_start, &ci->m_end, ci->m_cTypeName, parentvft, parentCount, &RTTI::vfTableList[i]);
				//vftable::correctFunctions(ci->m_cTypeName);
				ci->m_done = true;
				//msgR("***** Done %s\n", ci->m_cTypeName);
			}
		}

		msg("Vftable scan time: %.3f\n", (getTimeStamp() - startTime));
    }
    CATCH()
    return(FALSE);
}

#ifndef __EA64__
#define is_integer is_dword
#else
#define is_integer is_qword
#endif

size_t dumpClassMember(FILE* f, member_t* member, size_t fullSize, LPSTR className, size_t desiredOffset, size_t nextOffset, size_t currentOffset, bool skipBases = false)
{
	char szClassExport[MAXSTR] = "";
	qstring typeName = "";
	qstring endName = "";
	char szName[MAXSTR] = "";
	qstring cmnt;
	tid_t m = member->id;
	qstring mn = get_member_name(m);
	if (mn.c_str())
		strncpy(szName, mn.c_str(), (MAXSTR - 1));
	size_t nc = get_member_cmt(&cmnt, m, false);
	bool found = false;
	bool noTif = true;
	bool isPointer = false;
	tinfo_t tif;
	if (get_member_tinfo(&tif, member))
	{
		//msgR(" ** %s.             : size:%d at offset:%d, next:" EAFORMAT ", member:" EAFORMAT " tif:" EAFORMAT " **\n", className, fullSize, desiredOffset, nextOffset, member, tif);
		noTif = false;
		if (tif.get_type_name(&typeName))
		{
			//msgR(" ** %s.             : size:%d at offset:%d, next:" EAFORMAT ", member:" EAFORMAT " tif:" EAFORMAT " type:%s **\n", className, fullSize, desiredOffset, nextOffset, member, tif, typeName.c_str());
			found = true;
		}
		else
		{
			tif.get_realtype(false);
			if (tif.get_type_name(&typeName))
			{
				//msgR(" ** %s.             : size:%d at offset:%d, next:" EAFORMAT ", member:" EAFORMAT " tif:" EAFORMAT " real type:%s **\n", className, fullSize, desiredOffset, nextOffset, member, tif, typeName.c_str());
				found = true;
			}
			else
			{
				//msgR(" ** %s.             : size:%d at offset:%d, next:" EAFORMAT ", member:" EAFORMAT " tif:" EAFORMAT " no type **\n", className, fullSize, desiredOffset, nextOffset, member, tif);
				if (tif.is_signed())
					typeName.cat_sprnt("signed ");
				if (tif.is_unsigned())
					typeName.cat_sprnt("unsigned ");
				if (tif.is_array())
				{
					array_type_data_t data;
					if (tif.get_array_details(&data))
					{
						if (data.elem_type.get_type_name(&typeName))
						{
							//msgR(" ** %s.             : size:%d at offset:%d, next:" EAFORMAT ", member:" EAFORMAT " tif:" EAFORMAT " array:%s **\n", className, fullSize, desiredOffset, nextOffset, member, data.elem_type, typeName.c_str());
							found = true;
						}
						else
						{
							//msgR(" ** %s.             : size:%d at offset:%d, next:" EAFORMAT ", member:" EAFORMAT " tif:" EAFORMAT " array **\n", className, fullSize, desiredOffset, nextOffset, member, data.elem_type);
						}
						endName.cat_sprnt("[%d]", data.nelems);
					}
				}
				if (tif.is_ptr())
				{
					isPointer = true;
					ptr_type_data_t data;
					if (tif.get_ptr_details(&data))
					{
						if (data.obj_type.get_type_name(&typeName))
						{
							//msgR(" ** %s.             : size:%d at offset:%d, next:" EAFORMAT ", member:" EAFORMAT " tif:" EAFORMAT " pointer:%s **\n", className, fullSize, desiredOffset, nextOffset, member, data.obj_type, typeName.c_str());
							typeName.cat_sprnt("*");
							found = true;
						}
						else
						{
							//msgR(" ** %s.             : size:%d at offset:%d, next:" EAFORMAT ", member:" EAFORMAT " tif:" EAFORMAT " pointer **\n", className, fullSize, desiredOffset, nextOffset, member, data.obj_type);
						}
					}
				}
			}
		}
	}
	if (!found)
	{
		//msgR(" ** %s.             : size:%d at offset:%d, next:" EAFORMAT ", member:" EAFORMAT " not found (flag:" EAFORMAT ") **\n", className, fullSize, desiredOffset, nextOffset, member, member->flag);
		//if (isUnsigned(member->flag))
		//	typeName.cat_sprnt("*");
		if (is_integer(member->flag))
			typeName.cat_sprnt("int");
		else if (is_dword(member->flag))
			typeName.cat_sprnt("long");
		else if (is_word(member->flag))
			typeName.cat_sprnt("short");
		else if (is_byte(member->flag))
			typeName.cat_sprnt("char");
		else if (is_float(member->flag))
			typeName.cat_sprnt("float");
		else if (is_double(member->flag))
			typeName.cat_sprnt("double");
		if (isPointer || (member->flag & off_flag()))
			typeName.cat_sprnt("*");
	}

	//msgR(" ** %s.             : size:%d at offset:%d, next:" EAFORMAT ", member:" EAFORMAT " **\n", className, fullSize, desiredOffset, nextOffset, member);
	if (!skipBases || 0 == strstr(szName, "baseName")) {
		::qsnprintf(szClassExport, (MAXSTR - 1), "\t%s	%s%s;\t// %04X %s", typeName.c_str(), szName, endName.c_str(), currentOffset, cmnt.c_str());
		qfprintf(f, "%s\n", szClassExport);
	}
	return get_member_size(member);
}

void dumpVFTold(FILE* f, RTTI::classInfo *ci, RTTI::classInfo *ci2, bool translate)
{
	char szClassExport[MAXSTR] = "";
	UINT iCount = (ci->m_end - ci->m_start) / sizeof(ea_t);
	::qsnprintf(szClassExport, (MAXSTR - 1), "\t// %s %6d virtual funcs from " EAFORMAT " to " EAFORMAT "",
		ci->m_className, iCount, ci->m_start, ci->m_end);
	qfprintf(f, "%s\n", szClassExport);
	UINT iIndex = 0;
	for (ea_t eaAddress = ci->m_start; eaAddress < ci->m_end; eaAddress += sizeof(ea_t))
	{
		char memberName[MAXSTR] = "";
		ea_t eaMember = vftable::getMemberName(memberName, eaAddress);
		bool isThisClass = vftable::IsClass(ci->m_cTypeName, memberName, translate);
		bool noClass = (0 == strstr(memberName, "::"));
		if (/*true ||*/ isThisClass || noClass)
		{
			LPCSTR sz = NULL;
			if (isThisClass)
				sz = memberName + strlen(ci->m_cTypeName) + 2;
			else
				sz = memberName;
			::qsnprintf(szClassExport, (MAXSTR - 1), "\t%s\tvirtual int %s%s%s();\t// %04X " EAFORMAT " " EAFORMAT "",
				(BADADDR == eaMember) || !(isThisClass || noClass) ? "//" : "", ci2 && !noClass ? ci2->m_className : "", ci2 || noClass ? "::" : "", sz, iIndex,
				eaAddress, eaMember);
			qfprintf(f, "%s\n", szClassExport);
		}
		iIndex++;
	}
}

void dumpVFT(FILE* f, RTTI::classInfo *ci, RTTI::classInfo *ci2, vftable::VFMemberList *ml, bool translate,
	LPCSTR parentName = NULL, UINT startIndex = 0, UINT endIndex = 0)
{
	char szClassExport[MAXSTR] = "";
	LPCSTR sc = NULL;
	ea_t start, end;
	start = ci->m_start + startIndex * sizeof(ea_t);
	if (start > ci->m_end)
		start = ci->m_end;
	if (endIndex)
		end = ci->m_start + endIndex * sizeof(ea_t);
	else
		end = ci->m_end;
	if (parentName)
		sc = parentName;
	else
		sc = ci->m_className;
	UINT iCount = (end - start) / sizeof(ea_t);
	::qsnprintf(szClassExport, (MAXSTR - 1), "\t// %s %6d virtual funcs from " EAFORMAT " to " EAFORMAT "",
		sc, iCount, start, end);
	qfprintf(f, "%s\n", szClassExport);
	size_t maxLen = 0;
	if (ml)
	{
		UINT iIndex = startIndex;
		for (ea_t eaAddress = start; eaAddress < end; eaAddress += sizeof(ea_t))
		{
			if (ml->size() > iIndex)
			{
				vftable::EntryInfo ei = (*ml)[iIndex];
				ea_t eaMember = ei.member;
				bool isThisClass = ei.className == ci->m_cTypeName;
				bool noClass = (0 == ei.memberName.length());
				if ((optionDumpIdentical || !ei.IsIdentical()))
				{
					qstring sz;
					if (ei.memberName.length())
						sz = ei.memberName;
					else
						sz = ei.defaultName;
					if (sz.length() > maxLen)
						maxLen = sz.length();
				}
			}
			else
				msgR("\t\t\t** %s.DUMP_VFT() iIndex (%d) not smaller than original size (%d) **\n", sc, iIndex, ml->size());
			iIndex++;
		}
		iIndex = startIndex;
		for (ea_t eaAddress = start; eaAddress < end; eaAddress += sizeof(ea_t))
		{
			vftable::EntryInfo ei = (*ml)[iIndex];
			ea_t eaMember = ei.member;
			bool isThisClass = ei.className == ci->m_cTypeName;
			bool noClass = (0 == ei.memberName.length());
			if ((optionDumpIdentical || !ei.IsIdentical()))
			{
				qstring sz;
				bool showFullName;
				if (ei.memberName.length())
				{
					sz = ei.memberName;
					showFullName = false;
				}
				else
				{
					sz = ei.defaultName;
					showFullName = !ei.isDefault;
				}
				while (sz.length() < maxLen) sz += ' ';
				::qsnprintf(szClassExport, (MAXSTR - 1), "\t%s\tvirtual int %s%s%s();\t// %04X " EAFORMAT " " EAFORMAT " %s %s",
					(BADADDR == eaMember) || ei.IsIdentical() ? "//" : "", ci2 && !noClass ? ci2->m_className : "", ci2 && !noClass ? "::" : "", sz.c_str(), iIndex,
					eaAddress, eaMember, showFullName ? ei.fullName.c_str() : "", ei.typeName.c_str());
				qfprintf(f, "%s\n", szClassExport);
			}
			iIndex++;
		}
	}
}

void dumpClassMembersOld(FILE* f, RTTI::classInfo aCI, bool translate, bool hpp)
{
	//msgR(" ** %s.DUMP_MEMBERS() **\n", aCI.m_classname);

	UINT size = (UINT)aCI.m_parents.size();
	char szClassExport[MAXSTR] = "";
	char plainName[MAXSTR] = "";

	if (hpp)
	{
		if (size)
		{
			::qsnprintf(szClassExport, (MAXSTR - 1), "\t// handling %d parent class(es): ", size);
			qfprintf(f, "%s", szClassExport);
			for (UINT j = 0; j < size; j++)
			{
				RTTI::classInfo* ci = &RTTI::classList[aCI.m_parents[j]];
				::qsnprintf(szClassExport, (MAXSTR - 1), "%s ", ci->m_className);
				qfprintf(f, "%s", szClassExport);
			}
			qfprintf(f, "\n\n");
		}
		dumpVFTold(f, &aCI, NULL, translate);
		for (UINT j = 1; j < size; j++)
		{
			RTTI::classInfo* ci2 = &RTTI::classList[aCI.m_parents[j]];
			RTTI::classInfo* ci = ci2;
			if (j) // not direct parent
			{
				::qsnprintf(plainName, (MAXSTR - 1), "%s::%s", aCI.m_className, ci2->m_className);
				ci = RTTI::findClassInList(plainName);
			}
			if (ci)
				dumpVFTold(f, ci, ci2, translate);
			//else
			//	msgR(" ** %s.DUMP_MEMBERS(): missing class: '%s' **\n", aCI.m_className, plainName);
		}
		qfprintf(f, "\n");
	}

	tid_t t = get_struc_id(aCI.m_cTypeName);
	struc_t * strucPtr = get_struc(t);
	size_t memberCount = strucPtr ? strucPtr->memqty : 0;

	size_t fullSize = strucPtr ? get_struc_size(t) : 0;
	size_t usedSize = (aCI.m_vft && size == 0) ? sizeof(ea_t) : 0;			// vtbl if no baseClasses

	//msgR(" ** %s.DUMP_MEMBERS(): size:%d at offset:%d **\n", aCI.m_className, fullSize, usedSize);

	UINT i;
	for (i = 0; i < size; i++)
	{
		RTTI::classInfo c = RTTI::classList[aCI.m_parents[i]];
		usedSize += c.m_sizeFound ? c.m_size : sizeof(ea_t);
	}
	//msgR(" ** %s.DUMP_MEMBERS(): size:%d at offset:%d, start:%d, count:%d**\n", aCI.m_className, fullSize, usedSize, i, memberCount);

	member_t * member;
	for (asize_t j = (asize_t)usedSize; j < fullSize;)
	{
		asize_t o = j;
		ea_t n;
		member = get_member(strucPtr, o);
		if (member)
			n = member->soff;
		else
		{
			n = get_struc_next_offset(strucPtr, o);
			if (BADADDR == n)
				n = (ea_t)fullSize;
		}
		//msgR(" ** %s.             : size:%d at offset:%d, next:" EAFORMAT ", member:" EAFORMAT " **\n", aCI.m_className, fullSize, o, n, member);
		if (n > j)
			if (j + sizeof(ea_t) <= n)
			{
				::qsnprintf(szClassExport, (MAXSTR - 1), "\tunsigned int	unk%04X;\t// %04X ", j, j);
				qfprintf(f, "%s\n", szClassExport);
				j += sizeof(ea_t);
			}
			else
				if (j + 4 <= n)
				{
					::qsnprintf(szClassExport, (MAXSTR - 1), "\tUInt32	dwd%04X;\t// %04X ", j, j);
					qfprintf(f, "%s\n", szClassExport);
					j += 4;
				}
				else
					if (j + 2 <= n)
					{
						::qsnprintf(szClassExport, (MAXSTR - 1), "\tUInt16	wrd%04X;\t// %04X ", j, j);
						qfprintf(f, "%s\n", szClassExport);
						j += 2;
					}
					else
					{
						::qsnprintf(szClassExport, (MAXSTR - 1), "\tUInt8	byt%04X;\t// %04X ", j, j);
						qfprintf(f, "%s\n", szClassExport);
						j += 1;
					}
		if (member)
			j += (asize_t)dumpClassMember(f, member, fullSize, aCI.m_cTypeName, o, n, j);
		usedSize = j;
		//msgR(" ** %s.ADD_MEMBER(): %s at offset:%d, **\n", aCI.m_className, szClassExport, o);
	}

	if (strucPtr && (member = get_member(strucPtr, (asize_t)fullSize)))	// variable size member to finish ?
	{
		//msgR(" ** %s.             : **\n", aCI.m_className);
		usedSize += dumpClassMember(f, member, fullSize, aCI.m_cTypeName, fullSize, member->soff, member->soff);
	}
	//msgR(" ** %s.______________: size:%d at offset:%d, start:%d, count:%d**\n", aCI.m_className, fullSize, usedSize, i, memberCount);
}

void dumpClassMembers(FILE* f, RTTI::classInfo aCI, vftable::VFMemberList aML, bool translate, bool hpp)
{
	//msgR(" ** %s.DUMP_MEMBERS() **\n", aCI.m_classname);

	size_t size = aCI.m_parents.size();
	char szClassExport[MAXSTR] = "";
	char plainName[MAXSTR] = "";
	char parentName[MAXSTR] = "";
	UINT parentCount = 0;

	if (hpp)
	{
		if (size)
		{
			::qsnprintf(szClassExport, (MAXSTR - 1), "\t// handling %d parent class(es): ", size);
			qfprintf(f, "%s", szClassExport);
			for (UINT j = 0; j < size; j++)
			{
				RTTI::classInfo* ci = &RTTI::classList[aCI.m_parents[j]];
				::qsnprintf(szClassExport, (MAXSTR - 1), "%s ", ci->m_className);
				qfprintf(f, "%s", szClassExport);
				if (0 == j)
				{
					strcpy_s(parentName, ci->m_className);
					parentCount = (ci->m_end - ci->m_start) / sizeof(ea_t);
				}
			}
			qfprintf(f, "\n\n");
		}
		if (parentCount)
		{
			dumpVFT(f, &aCI, NULL, &aML, translate, parentName, 0, parentCount);
			dumpVFT(f, &aCI, NULL, &aML, translate, NULL, parentCount, 0);
		}
		else
			dumpVFT(f, &aCI, NULL, &aML, translate);

		for (UINT j = 1; j < size; j++)
		{
			UINT p = aCI.m_parents[j];
			RTTI::classInfo* ci2 = &RTTI::classList[p];
			vftable::VFMemberList* ml2 = NULL;
			RTTI::classInfo* ci = NULL;
			::qsnprintf(plainName, (MAXSTR - 1), "%s::%s", aCI.m_className, ci2->m_className);
			int k = RTTI::findIndexInList(plainName);
			if (k >= 0 && k < (int)RTTI::vfTableList.size())
			{
				ci = &RTTI::classList[k];
				ml2 = &RTTI::vfTableList[k];
			}
			if (ci)
				dumpVFT(f, ci, ci2, ml2, translate);
			//else
			//	msgR(" ** %s.DUMP_MEMBERS(): missing class: '%s' **\n", aCI.m_className, plainName);
		}
		qfprintf(f, "\n");
	}

	tid_t t = get_struc_id(aCI.m_cTypeName);
	struc_t * strucPtr = get_struc(t);
	size_t memberCount = strucPtr ? strucPtr->memqty : 0;

	size_t fullSize = strucPtr ? get_struc_size(t) : 0;
	size_t usedSize = (aCI.m_vft && size == 0) ? sizeof(ea_t) : 0;			// vtbl if no baseClasses

	//msgR(" ** %s.DUMP_MEMBERS(): size:%d at offset:%d **\n", aCI.m_className, fullSize, usedSize);

	UINT i;
	for (i = 0; i < size; i++)
	{
		RTTI::classInfo c = RTTI::classList[aCI.m_parents[i]];
		size_t ms = c.m_sizeFound ? c.m_size : 0;
		if (0 == ms) {  // is the struc sized ?
			tid_t mt = get_struc_id(c.m_cTypeName);
			struc_t * mStrucPtr = get_struc(mt);
			ms = mStrucPtr ? get_struc_size(mt) : 0;
		};
		usedSize += ms ? ms : sizeof(ea_t);  // at least one pointer long
	}
	//msgR(" ** %s.DUMP_MEMBERS(): size:%d at offset:%d, start:%d, count:%d**\n", aCI.m_className, fullSize, usedSize, i, memberCount);

	member_t * member;
	for (size_t j = usedSize; j < fullSize;)
	{
		ea_t o = (ea_t)j;
		ea_t n;
		member = get_member(strucPtr, o);
		if (member)
			n = member->soff;
		else
		{
			n = get_struc_next_offset(strucPtr, o);
			if (BADADDR == n)
				n = (ea_t)fullSize;
		}
		//msgR(" ** %s.             : size:%d at offset:%d, next:" EAFORMAT ", member:" EAFORMAT " **\n", aCI.m_className, fullSize, o, n, member);
		if (n > j)
			if (j + sizeof(ea_t) <= n)
			{
				::qsnprintf(szClassExport, (MAXSTR - 1), "\tunsigned int	unk%04X;\t// %04X ", j, j);
				qfprintf(f, "%s\n", szClassExport);
				j += sizeof(ea_t);
			}
			else
				if (j + 4 <= n)
				{
					::qsnprintf(szClassExport, (MAXSTR - 1), "\tUInt32	dwd%04X;\t// %04X ", j, j);
					qfprintf(f, "%s\n", szClassExport);
					j += 4;
				}
				else
					if (j + 2 <= n)
					{
						::qsnprintf(szClassExport, (MAXSTR - 1), "\tUInt16	wrd%04X;\t// %04X ", j, j);
						qfprintf(f, "%s\n", szClassExport);
						j += 2;
					}
					else
					{
						::qsnprintf(szClassExport, (MAXSTR - 1), "\tUInt8	byt%04X;\t// %04X ", j, j);
						qfprintf(f, "%s\n", szClassExport);
						j += 1;
					}
		if (member)
			j += dumpClassMember(f, member, fullSize, aCI.m_cTypeName, o, n, j, hpp);
		usedSize = j;
		//msgR(" ** %s.ADD_MEMBER(): %s at offset:%d, **\n", aCI.m_className, szClassExport, o);
	}

	if (strucPtr && (member = get_member(strucPtr, (asize_t)fullSize)))	// variable size member to finish ?
	{
		//msgR(" ** %s.             : **\n", aCI.m_className);
		usedSize += dumpClassMember(f, member, fullSize, aCI.m_cTypeName, fullSize, member->soff, member->soff);
	}
	//msgR(" ** %s.______________: size:%d at offset:%d, start:%d, count:%d**\n", aCI.m_className, fullSize, usedSize, i, memberCount);
}

char THEprefix[MAXSTR] = "";
static char lastError[MAXSTR] = "";
static int funcIndex = 0;

bool LookupFuncToName(func_t *funcTo, size_t index, size_t level, char * funcFromName, FILE* f)
{
	bool result = TRUE;
	//char szClassExport[MAXSTR] = "";
	xrefblk_t xb;
	if (funcTo && (optionIterLevels > level))
	{
		strcat_s(THEprefix, "  ");
		flags_t flags = get_flags(funcTo->start_ea);
		if (!has_name(flags) || has_dummy_name(flags))
		{
			char funcToName[MAXSTR] = "";
			{
				qstring fN;
				if (get_visible_name(&fN, funcTo->start_ea))
					RTTI::ReplaceForCTypeName(funcToName, fN.c_str());
			}
			UINT callIndex = 0;
			//::qsnprintf(szClassExport, MAXSTR - 1, "//\t%sxref to %s " EAFORMAT " at level %d for index %d", THEprefix, funcToName, funcTo->start_ea, level, index);
			//qfprintf(f, "%s\n", szClassExport);
			for (bool ok = xb.first_to(funcTo->start_ea, XREF_ALL); ok; ok = xb.next_to())
			{
				callIndex++;
				// xb.from - contains the referencing address
				char funcName[MAXSTR] = "";
				func_t* funcFrom = get_func(xb.from);
				if (funcFrom && (funcFrom->start_ea != funcTo->start_ea))
				{
					flags_t funcFromFlags = get_flags(funcFrom->start_ea);
					if (!has_name(funcFromFlags) || has_dummy_name(funcFromFlags))
						if (!LookupFuncToName(funcFrom, ++funcIndex, ++level, funcName, f))
							break;
					if (has_name(funcFromFlags) && !has_dummy_name(funcFromFlags))
					{
						qstring fN;
						if (get_visible_name(&fN, funcFrom->start_ea))
							RTTI::ReplaceForCTypeName(funcName, fN.c_str());
						else
							strcpy_s(funcName, "NONAME__");
						//::qsnprintf(szClassExport, MAXSTR - 1, "//\t%sxref to %s " EAFORMAT " : From:" EAFORMAT " Func:" EAFORMAT " '%s'",
						//	THEprefix, funcToName, funcTo->start_ea, xb.from, funcFrom ? funcFrom->start_ea : BADADDR, funcName);
						//qfprintf(f, "%s\n", szClassExport);
						//msgR("%s\n", szClassExport);
						char newFuncName[MAXSTR] = "";
						::qsnprintf(funcFromName, MAXSTR - 1, "%s%s_from%0.4d", strstr(funcName, "__ICI__") ? "" : "__ICI__", funcName, index);
						//::qsnprintf(newFuncName, MAXSTR - 1, "//\t\t%srenamed to '%s'", THEprefix, funcFromName);
						//qfprintf(f, "%s\n", newFuncName);
						if (!(0 == stricmp(lastError, funcFromName)))
							if (!set_name(funcTo->start_ea, funcFromName))
								strcpy_s(lastError, funcFromName);
							else
								break;	// We use the first name we can find
					}
				};
			}
			if (0 == callIndex)
				result = FALSE;
		}
		else
		{
			qstring fN;
			if (get_visible_name(&fN, funcTo->start_ea))
				RTTI::ReplaceForCTypeName(funcFromName, fN.c_str());
			//char newFuncName[MAXSTR] = "";
			//::qsnprintf(newFuncName, MAXSTR - 1, "//\t\t%sfound named as '%s'", THEprefix, funcFromName);
			//qfprintf(f, "%s\n", newFuncName);
		}
		THEprefix[strlen(THEprefix) - 2] = 0;
	}
	return result;
}

bool LookupFuncFromName(func_t *funcFrom, size_t index, size_t level, char * funcToName, FILE* f)
{
	bool result = TRUE;
	char szClassExport[MAXSTR] = "";
	xrefblk_t xb;
	UINT callIndex = 0;
	UINT found = 0;
	flags_t flags = get_flags(funcFrom->start_ea);
	char funcFromName[MAXSTR] = "";
	{
		qstring fN;
		if (get_visible_name(&fN, funcFrom->start_ea))
			RTTI::ReplaceForCTypeName(funcFromName, fN.c_str());
		else
			return FALSE;
	}
	strcat_s(THEprefix, "  ");
	if (optionIterLevels > level)
		for (ea_t eaCurr = funcFrom->start_ea; eaCurr < funcFrom->end_ea; eaCurr = next_addr(eaCurr))
		{
			callIndex++;
			//::qsnprintf(szClassExport, MAXSTR - 1, "//\t%scref from '%s' " EAFORMAT " at level %d for index %d", THEprefix, funcFromName, eaCurr, level, index);
			//qfprintf(f, "%s\n", szClassExport);
			//strcat_s(THEprefix, "  ");
			for (bool ok = xb.first_from(eaCurr, XREF_FAR); ok; ok = xb.next_from())
			{
				char funcName[MAXSTR];
				{
					qstring fN;
					if (get_visible_name(&fN, xb.to))
						RTTI::ReplaceForCTypeName(funcName, fN.c_str());
					else
						strcpy_s(funcName, "NONAME__");
				}
				//::qsnprintf(szClassExport, MAXSTR - 1, "//\t%scref from '%s' " EAFORMAT " : To:" EAFORMAT " '%s'",
				//	THEprefix, funcFromName, eaCurr, xb.to, funcName);
				//qfprintf(f, "%s\n", szClassExport);
				func_t* funcTo = get_func(xb.to);
				if (funcTo && (funcTo->start_ea != funcFrom->start_ea))
				{
					//::qsnprintf(szClassExport, MAXSTR - 1, "//\t%scref from '%s' " EAFORMAT " : To:" EAFORMAT " Func:" EAFORMAT,
					//	THEprefix, funcFromName, eaCurr, xb.to, funcTo ? funcTo->start_ea : BADADDR);
					//qfprintf(f, "%s\n", szClassExport);
					flags_t funcToFlags = get_flags(funcTo->start_ea);
					if (!has_name(funcToFlags) || has_dummy_name(funcToFlags))
					{
						{
							qstring fN;
							if (get_visible_name(&fN, funcTo->start_ea))
								RTTI::ReplaceForCTypeName(funcName, fN.c_str());
							else
								strcpy_s(funcName, "NONAME__");
						}
						char newFuncName[MAXSTR] = "";
						::qsnprintf(funcToName, MAXSTR - 1, "%s%s_to%0.4d", strstr(funcFromName, "__ICI__") ? "" : "__ICI__",
							strlen(funcFromName) ? funcFromName : "NONAME__", callIndex);
						//::qsnprintf(szClassExport, MAXSTR - 1, "//\t%scref from '%s' " EAFORMAT " : To:" EAFORMAT " Func:" EAFORMAT " '%s' changed to '%s'",
						//	THEprefix, funcFromName, eaCurr, xb.to, funcTo ? funcTo->start_ea : BADADDR, funcName, funcToName);
						//qfprintf(f, "%s\n", szClassExport);
						//msgR("%s\n", szClassExport);
						//qfprintf(f, "%s\n", newFuncName);
						if (!(0 == stricmp(lastError, funcToName)))
							if (!set_name(funcTo->start_ea, funcToName))
								strcpy_s(lastError, funcToName);
							else
								found++;
						funcToFlags = get_flags(funcTo->start_ea);
						if (has_name(funcToFlags) && !has_dummy_name(funcToFlags))
							if (!LookupFuncFromName(funcTo, callIndex, ++level, funcName, f))
								break;
					}
				};
			}
		}
	if (0 == found)
		result = FALSE;
	//else
	//	qfprintf(f, "\n");
	//THEprefix[strlen(THEprefix) - 2] = 0;
	THEprefix[strlen(THEprefix) - 2] = 0;
	return result;
}

static BOOL dumpVftables()
{
#ifndef __DEBUG
	try
#endif
	{
		char szClass[MAXSTR] = "";
		char szTemplate[MAXSTR] = "none";
		char szClassDef[MAXSTR] = "";
		char szClassExport[MAXSTR] = "";
		::qsnprintf(szClassExport, (MAXSTR - 1), "classIndex;className;colName;vft;col;start;end;vftCount;parentCount;baseClassIndex;IsTemplate;TemplateTypeCount");
		qfprintf(fClass, "%s\n", szClassExport);
		::qsnprintf(szClassExport, (MAXSTR - 1), "classIndex;parentIndex;parentName;parentColName;attribute");
		qfprintf(fClassHierarchy, "%s\n", szClassExport);
		::qsnprintf(szClassExport, (MAXSTR - 1), "classIndex;memberIndex;memberName;vftOffset;memberOffset");
		qfprintf(fClassMembers, "%s\n", szClassExport);

		::qsnprintf(szClassExport, (MAXSTR - 1), "//	extern const void * RTTI_%s", "className");
		qfprintf(fClassRTTI, "%s\n", szClassExport);

		::qsnprintf(szClassExport, (MAXSTR - 1), "//	const void * RTTI_className = (void*)0x0000000000000000");
		qfprintf(fClassRTTIinl, "%s\n", szClassExport);

		for (UINT index = RTTI::classPKeys.size(); index > 0;)
		{
			UINT k = RTTI::classPKeys.size() - index;
			if (0 == k % 100)
				msgR("\t\t%35s Class:\t% 7d of % 7d\n", "Looking for xref to vtable offset:", k + 1, RTTI::classPKeys.size());

			index--;
			UINT i = RTTI::classPKeys[index].index;
			RTTI::classInfo aCI = RTTI::classList[i];
			if (0 == strstr(aCI.m_className, "::"))
			{
				bool isAllocation = false;
				bool diffAmount = false;
				size_t amount = 0;
				size_t lastAmount = 0;
				func_t* funcFrom = NULL;
				xrefblk_t xb;
				for (bool ok = xb.first_to(aCI.m_vft, XREF_ALL); ok; ok = xb.next_to())
				{
					// xb.from - contains the referencing address
					char funcName[MAXSTR] = "";
					funcFrom = get_func(xb.from);
					if (funcFrom)
					{
						qstring fN;
						if (get_long_name(&fN, funcFrom->start_ea))
							strncpy(funcName, fN.c_str(), (MAXSTR - 1));
					}
					::qsnprintf(szClassExport, MAXSTR - 1, "//\txref to %s::'vftable' " EAFORMAT " : From:" EAFORMAT " Func:" EAFORMAT " '%s'",
						aCI.m_className, aCI.m_vft, xb.from, funcFrom ? funcFrom->start_ea : BADADDR, funcName);
					qfprintf(fClassInc, "%s\n", szClassExport);
					//msgR("%s\n", szClassExport);
					isAllocation = RTTI::checkForInlineAllocationPattern(xb.from, &amount);

					if (isAllocation)
					{
						::qsnprintf(szClassExport, MAXSTR - 1, "#define __ICI__%s__size %6d // vft:" EAFORMAT " : inline:" EAFORMAT " ",
							aCI.m_className, amount, aCI.m_vft, xb.from);
						qfprintf(fClassInc, "%s\n", szClassExport);
						if (lastAmount)
						{
							if (lastAmount != amount)
								diffAmount = true;
						}
						else
							lastAmount = amount;
						recordConstructor(xb.from, aCI.m_cTypeName, aCI, amount, i);
					}
					else if (funcFrom)
					{
						xrefblk_t xbp;
						for (bool ok = xbp.first_to(funcFrom->start_ea, XREF_ALL); ok; ok = xbp.next_to())
						{
							// xb.from - contains the referencing address
							char funcName[MAXSTR] = "";
							func_t* funcFromParent = get_func(xbp.from);
							bool done = false;
							if (funcFromParent)
							{
								qstring fN;
								if (get_long_name(&fN, funcFromParent->start_ea))
									strncpy(funcName, fN.c_str(), (MAXSTR - 1));
								BYTE b = get_byte(xbp.from);
								if (b == 0x0E9 || b == 0xEB) // its a jmp, let's look at the xref
								{
									done = true;
									xrefblk_t xbj;
									for (bool ok = xbj.first_to(funcFromParent->start_ea, XREF_ALL); ok; ok = xbj.next_to())
									{
										// xb.from - contains the referencing address
										char funcName[MAXSTR] = "";
										func_t* funcFromJump = get_func(xbj.from);
										if (funcFromJump)
										{
											qstring fN;
											if (get_long_name(&fN, funcFromJump->start_ea))
												strncpy(funcName, fN.c_str(), (MAXSTR - 1));
										}
										//::qsnprintf(szClassExport, MAXSTR - 1, "//\t'%s' " EAFORMAT " : jump:" EAFORMAT " From:" EAFORMAT " Func:" EAFORMAT " '%s'",
										//	aCI.m_classname, aCI.m_vft, funcFrom->start_ea, xbj.from, funcFromJump ? funcFromJump->start_ea : BADADDR, funcName);
										//qfprintf(fClassInc, "%s\n", szClassExport);
										isAllocation = RTTI::checkForAllocationPattern(xbj.from, &amount);
										if (isAllocation)
										{
											::qsnprintf(szClassExport, MAXSTR - 1, "#define __ICI__%s__size %6d // vft:" EAFORMAT " : constructor:" EAFORMAT " ",
												aCI.m_cTypeName, amount, aCI.m_vft, funcFrom->start_ea);
											qfprintf(fClassInc, "%s\n", szClassExport);
											makeConstructor(funcFrom, aCI.m_cTypeName, aCI, amount, i);
											if (lastAmount)
											{
												if (lastAmount != amount)
													diffAmount = true;
											}
											else
												lastAmount = amount;
										}
									}
								}
								//else
								//{
								//	::qsnprintf(szClassExport, MAXSTR - 1, "//\t'%s' " EAFORMAT " : call:" EAFORMAT " %x",
								//		aCI.m_classname, aCI.m_vft, funcFrom->start_ea, b);
								//	qfprintf(fClassInc, "%s\n", szClassExport);
								//}
							}
							if (!done)
							{
								//::qsnprintf(szClassExport, MAXSTR - 1, "//\t'%s' " EAFORMAT " : xref:" EAFORMAT " From:" EAFORMAT " Func:" EAFORMAT " '%s'",
								//	aCI.m_classname, aCI.m_vft, funcFrom->start_ea, xbp.from,
								//	funcFromParent ? funcFromParent->start_ea : BADADDR, funcName);
								//qfprintf(fClassInc, "%s\n", szClassExport);
								isAllocation = RTTI::checkForAllocationPattern(xbp.from, &amount);
								if (isAllocation)
								{
									::qsnprintf(szClassExport, MAXSTR - 1, "#define __ICI__%s__size %6d // vft:" EAFORMAT " : constructor:" EAFORMAT " ",
										aCI.m_cTypeName, amount, aCI.m_vft, funcFrom->start_ea);
									qfprintf(fClassInc, "%s\n", szClassExport);
									makeConstructor(funcFrom, aCI.m_cTypeName, aCI, amount, i);
								}
								if (lastAmount)
								{
									if (lastAmount != amount)
										diffAmount = true;
								}
								else
									lastAmount = amount;
							}
						}
					}
				}
				if (lastAmount && !diffAmount)
					RTTI::recordSize(aCI, amount, i);
				qfprintf(fClassInc, "\n");
			}
		}

		UINT cpks = RTTI::classPKeys.size();
		for (UINT i = 0; i < cpks; i++)
		{
			if (0 == i % 100)
				msgR("\t\t%35s Class:\t% 7d of % 7d\n", "Updating struc size:", i + 1, cpks);

			//msgR("\t\t%35s Class:\t% 7d of % 7d : % 6d (%s)\n", "Updating struc size:", i + 1, cpks, RTTI::classList[RTTI::classPKeys[i].index].m_parents.size(),
			//	RTTI::classList[RTTI::classPKeys[i].index].m_className);
			RTTI::classInfo* aCI = &RTTI::classList[RTTI::classPKeys[i].index];
			if (aCI->m_parents.size() > 1)
			{
				UINT lastIndex = aCI->m_parents[1];
				UINT lastOffset = 0;
				//msgR("\t\t%35s Class:\t% 7d of % 7d looking at %d (%s)\n", "Updating struc size:", i + 1, cpks, lastIndex,
				//	RTTI::classList[lastIndex].m_classname);
				for (UINT j = 2; j < aCI->m_parents.size(); j++)
				{
					UINT p = aCI->m_parents[j];
					RTTI::classInfo* ci = &RTTI::classList[p];
					if (ci)
					{
						//msgR("\t\t%35s Class:\t% 7d of % 7d looking at %d (%s) offset=%d\n", "Updating struc size:", i + 1, cpks, lastIndex,
						//	RTTI::classList[lastIndex].m_classname, lastOffset);
						UINT offset = 0;
						char ComposedName[MAXSTR] = "";
						strcpy_s(ComposedName, aCI->m_className);
						strcat_s(ComposedName, "::");
						strcat_s(ComposedName, ci->m_className);
						if (RTTI::classInfo* ci2 = RTTI::findClassInList(ComposedName))
						{
							//msgR("\t\t%35s Class:\t% 7d of % 7d looking for %d (%s) offset=%d\n", "Updating struc size:", i + 1, cpks, lastIndex,
							//	ComposedName, lastOffset);
							offset = RTTI::getClassOffset(ci2->m_vft, ci2->m_col);
							if (!RTTI::classList[lastIndex].m_sizeFound)
							{
								RTTI::classList[lastIndex].m_sizeFound = true;
								RTTI::classList[lastIndex].m_size = offset - lastOffset;
								//msgR("\t\t%35s Class:\t% 7d of % 7d Size found for %d (%s): %d\n", "Updating struc size:", i + 1, cpks,
								//	lastIndex, RTTI::classList[lastIndex].m_className, offset - lastOffset);
							}
						}
						lastOffset = offset;
					}
					lastIndex = aCI->m_parents[j];
				}
			}
		}

		for (UINT i = 0; i < cpks; i++)
		{
			if (0 == i % 100)
				msgR("\t\t%35s Class:\t% 7d of % 7d\n", "Updating struc records:", i + 1, cpks);

			RTTI::addClassDefinitionsToIda(RTTI::classList[RTTI::classPKeys[i].index], true);
		}

		//return false;

		// Create IDC begining:
		qfprintf(fClassIdc, "#include <idc.idc>\n");
		qfprintf(fClassIdc, "\n");
		qfprintf(fClassIdc, "		extern pointerSize;\n");
		qfprintf(fClassIdc, "\n");
		qfprintf(fClassIdc, "		static GetRef(ea)\n");
		qfprintf(fClassIdc, "		{\n");
		qfprintf(fClassIdc, "			auto xea;\n");
		qfprintf(fClassIdc, "			if (pointerSize == 4)\n");
		qfprintf(fClassIdc, "				xea = Dword(ea);\n");
		qfprintf(fClassIdc, "			else\n");
		qfprintf(fClassIdc, "				xea = Qword(ea);\n");
		qfprintf(fClassIdc, "			return xea;\n");
		qfprintf(fClassIdc, "		}\n");
		qfprintf(fClassIdc, "\n");
		qfprintf(fClassIdc, "		static getRelJmpTarget(eaAddress)\n");
		qfprintf(fClassIdc, "		{\n");
		qfprintf(fClassIdc, "			auto bt = Byte(eaAddress);\n");
		qfprintf(fClassIdc, "			if (bt == 0xEB)\n");
		qfprintf(fClassIdc, "			{\n");
		qfprintf(fClassIdc, "				bt = Byte(eaAddress + 1);\n");
		qfprintf(fClassIdc, "				if (bt & 0x80)\n");
		qfprintf(fClassIdc, "					return (eaAddress + 2 - ((~bt & 0xFF) + 1));\n");
		qfprintf(fClassIdc, "				else\n");
		qfprintf(fClassIdc, "					return (eaAddress + 2 + bt);\n");
		qfprintf(fClassIdc, "			}\n");
		qfprintf(fClassIdc, "			else\n");
		qfprintf(fClassIdc, "				if (bt == 0xE9)\n");
		qfprintf(fClassIdc, "				{\n");
		qfprintf(fClassIdc, "					auto dw = Dword(eaAddress + 1);\n");
		qfprintf(fClassIdc, "					if (dw & 0x80000000)\n");
		qfprintf(fClassIdc, "						return (eaAddress + 5 - (~dw + 1));\n");
		qfprintf(fClassIdc, "					else\n");
		qfprintf(fClassIdc, "						return (eaAddress + 5 + dw);\n");
		qfprintf(fClassIdc, "				}\n");
		qfprintf(fClassIdc, "				else\n");
		qfprintf(fClassIdc, "					return(BADADDR);\n");
		qfprintf(fClassIdc, "		}\n");
		qfprintf(fClassIdc, "\n");
		qfprintf(fClassIdc, "		static DoFunc(ea, funcName, funcComment)\n");
		qfprintf(fClassIdc, "		{\n");
		qfprintf(fClassIdc, "			auto xea = GetRef(ea);\n");
		qfprintf(fClassIdc, "			auto jea = getRelJmpTarget(xea);\n");
		qfprintf(fClassIdc, "			if (jea == BADADDR)\n");
		qfprintf(fClassIdc, "			{\n");
		qfprintf(fClassIdc, "				if (funcName != \"\")\n");
		qfprintf(fClassIdc, "					MakeNameEx(xea, funcName, SN_NOCHECK + SN_PUBLIC + SN_NOWARN);\n");
		qfprintf(fClassIdc, "				else\n");
		qfprintf(fClassIdc, "				if (funcComment != \"\")\n");
		qfprintf(fClassIdc, "				{\n");
		qfprintf(fClassIdc, "					MakeComm(ea, funcComment);\n");
		qfprintf(fClassIdc, "				}\n");
		qfprintf(fClassIdc, "			}\n");
		qfprintf(fClassIdc, "			else\n");
		qfprintf(fClassIdc, "			{\n");
		qfprintf(fClassIdc, "				if (funcName != \"\")\n");
		qfprintf(fClassIdc, "				{\n");
		qfprintf(fClassIdc, "					MakeNameEx(xea, \"\", SN_NOCHECK + SN_PUBLIC + SN_NOWARN);\n");
		qfprintf(fClassIdc, "					MakeNameEx(jea, funcName, SN_NOCHECK + SN_PUBLIC + SN_NOWARN);\n");
		qfprintf(fClassIdc, "				}\n");
		qfprintf(fClassIdc, "				else\n");
		qfprintf(fClassIdc, "				if (funcComment != \"\")\n");
		qfprintf(fClassIdc, "				{\n");
		qfprintf(fClassIdc, "					MakeComm(ea, funcComment);\n");
		qfprintf(fClassIdc, "				}\n");
		qfprintf(fClassIdc, "			}\n");
		qfprintf(fClassIdc, "			ea = ea + pointerSize;\n");
		qfprintf(fClassIdc, "			return ea;\n");
		qfprintf(fClassIdc, "		}\n");
		qfprintf(fClassIdc, "\n");
		qfprintf(fClassIdc, "		static main(void)\n");
		qfprintf(fClassIdc, "		{\n");
		qfprintf(fClassIdc, "			pointerSize = sizeof(\"void *\");\n");
		qfprintf(fClassIdc, "			auto ea;\n");
		qfprintf(fClassIdc, "			auto vtblName;\n");
		qfprintf(fClassIdc, "\n");

		for (UINT i = 0; i < cpks; i++)
		{
			if (0 == i % 100)
				msgR("\t\t%35s Class:\t% 7d of % 7d\n", "Declare all classes:", i + 1, cpks);

			if (strchr(RTTI::classPKeys[i].pk, '1') == RTTI::classPKeys[i].pk)
			{
				UINT index = RTTI::classPKeys[i].index;
				if (0 == strstr(RTTI::classList[index].m_className, "::"))
				{
					qfprintf(fClassIncHpp, "class %s;\n", RTTI::classList[RTTI::classPKeys[i].index].m_className);
				}
			}
		}
		qfprintf(fClassIncHpp, "%s\n", "");

		for (UINT i = 0; i < cpks; i++)
		{
			if (0 == i % 100)
				msgR("\t\t%35s Class:\t% 7d of % 7d\n", "RTTI all classes:", i + 1, cpks);

			if (strchr(RTTI::classPKeys[i].pk, '1') == RTTI::classPKeys[i].pk)
			{
				UINT index = RTTI::classPKeys[i].index;
				ea_t ear;
				if (0 == strstr(RTTI::classList[index].m_className, "::") && (getVerify_t(RTTI::classList[index].m_vft - sizeof(ea_t), ear)))
				{
					ea_t ea = get_32bit(ear + 12);

					::qsnprintf(szClassExport, (MAXSTR - 1), "  	extern const void * RTTI_%s;", RTTI::classList[index].m_className);
					qfprintf(fClassRTTI, "%s\n", szClassExport);

					::qsnprintf(szClassExport, (MAXSTR - 1), "  	const void * RTTI_%s = (void*)0x" EAFORMAT ";",
						RTTI::classList[index].m_className, ea);
					qfprintf(fClassRTTIinl, "%s\n", szClassExport);
				}
			}
		}
		qfprintf(fClassRTTI, "%s\n", "");
		qfprintf(fClassRTTIinl, "%s\n", "");

		char szLastTemplate[MAXSTR] = "none";
		for (UINT i = 0; i < cpks; i++)
		{
			if (0 == i % 100)
				msgR("\t\t%35s Class:\t% 7d of % 7d\n", "Dump Templates:", i + 1, cpks);

			UINT index = RTTI::classPKeys[i].index;
			RTTI::classInfo aCI = RTTI::classList[index];
			vftable::VFMemberList aML = RTTI::vfTableList[index];
			if (0 == strstr(aCI.m_className, "::"))
			{
				char plainName[MAXSTR];
				char szTemplate[MAXSTR] = "template "; // "template<";
				bool isTemplate = aCI.m_templateInfo.m_template;
				//UINT typeCount = aCI.m_templateInfo.m_templateList.size();
				if (isTemplate && stricmp(szLastTemplate, aCI.m_templateInfo.m_templatename))
				{
					//msgR("\t\tTemplate: '%s' from '%s'\n", szLastTemplate, aCI.m_templateInfo.m_templatename);
					//if (isTemplate && typeCount)
					//{
					//	qfprintf(fClassIncHpp, "\n");
					//	char szI[10];
					//	for (UINT j = 0; j < typeCount - 1; j++)
					//	{
					//		strcat_s(szTemplate, "typename _T");
					//		strcat_s(szTemplate, _itoa(j, szI, 10));
					//		strcat_s(szTemplate, ", ");
					//	}
					//	strcat_s(szTemplate, "typename _T");
					//	strcat_s(szTemplate, _itoa(typeCount - 1, szI, 10));
					//	strcat_s(szTemplate, "> ");
					//	strcpy_s(szLastTemplate, aCI.m_templateInfo.m_templatename);
					//}
					UINT size = aCI.m_bcdlist.size();
					qfprintf(fClassIncHpp, "%sclass %s%s\n", isTemplate ? szTemplate : "",
						isTemplate ? aCI.m_templateInfo.m_templatename : aCI.m_className, size > 1 ? ": public" : "");
					for (UINT j = 1; j < size; j++)
					{
						getPlainTypeName(aCI.m_bcdlist[j].m_name, plainName);
						RTTI::classInfo* ci = RTTI::findClassInList(plainName);
						//for (UINT k = 0; k < typeCount; k++)
						//	RTTI::replaceTypeName(plainName, aCI.m_templateInfo, k);
						::qsnprintf(szClassExport, (MAXSTR - 1), "\t%s%s", plainName, ci ? (j + ci->m_numBaseClasses >= size ? "" : ",") : ",");
						qfprintf(fClassIncHpp, "%s\n", szClassExport);
						if (ci)
							j += (ci->m_numBaseClasses - 1);
					}
					qfprintf(fClassIncHpp, "{\n");
					dumpClassMembers(fClassIncHpp, aCI, aML, true, true);
					//dumpClassMembersOld(fClassIncTemp, aCI, true, true);
					qfprintf(fClassIncHpp, "}\t//\t%04X\n", aCI.m_size);
				}

				if (isTemplate)
				{
					UINT size = aCI.m_bcdlist.size();
					qfprintf(fClassIncHpp, "//\t%s%s", aCI.m_className, size > 1 ? ": public " : ";");
					for (UINT j = 1; j < size; j++)
					{
						getPlainTypeName(aCI.m_bcdlist[j].m_name, plainName);
						RTTI::classInfo* ci = RTTI::findClassInList(plainName);
						qfprintf(fClassIncHpp, "%s%s", plainName, ci ? (j + ci->m_numBaseClasses >= size ? ";" : ",") : ",");
						if (ci)
							j += (ci->m_numBaseClasses - 1);
					}
					qfprintf(fClassIncHpp, "\n");
				}
			}
		}
		qfprintf(fClassIncHpp, "\n");

		for (UINT i = 0; i < RTTI::classPKeys.size(); i++)
		{
			if (0 == i % 100)
				msgR("\t\t%35s Class:\t% 7d of % 7d\n", "Dump classes:", i + 1, RTTI::classList.size());

			UINT index = RTTI::classPKeys[i].index;
			RTTI::classInfo aCI = RTTI::classList[index];
			vftable::VFMemberList aML = RTTI::vfTableList[index];
			bool isTemplate = aCI.m_templateInfo.m_template;
			if (0 == strstr(aCI.m_className, "::") && !isTemplate)
			{
				char plainName[MAXSTR];
				char szTemplate[MAXSTR] = "template<";
				UINT size = aCI.m_bcdlist.size();
				qfprintf(fClassIncHpp, "%sclass %s%s\n", isTemplate ? "typedef " : "",
					aCI.m_className, size > 1 ? ": public" : "");
				UINT parentCount = 1;
				for (UINT j = 1; j < size; j++)
				{
					getPlainTypeName(aCI.m_bcdlist[j].m_name, plainName);
					RTTI::classInfo* ci = RTTI::findClassInList(plainName);
					qfprintf(fClassIncHpp, "\t%s%s\n", plainName, ci ? (j + ci->m_numBaseClasses >= size ? "" : ",") : ",");
					if (ci)
						j += (ci->m_numBaseClasses - 1);
					parentCount++;
				}
				qfprintf(fClassIncHpp, "{ //\tvft=" EAFORMAT "\n", (UINT)-1 != aCI.m_vft ? aCI.m_vft : 0);
				dumpClassMembers(fClassIncHpp, aCI, aML, false, true);
				qfprintf(fClassIncHpp, "};\t//\t%04X\n\n", aCI.m_size);

				if ((UINT)-1 != aCI.m_vft)
				{
					UINT nameCount = 0;
					for (UINT j = 0; j < aML.size(); j++)
					{
						vftable::EntryInfo e = aML[j];
						if (!e.IsDefault() && !e.IsIdentical() && !e.IsInherited())
							nameCount++;
					}
					if (nameCount)
					{
						// Start the class in IDC script
						qfprintf(fClassIdc, "				vtblName = \"%s\"; // '%s' '%s'\n", get_name(aCI.m_vft).c_str(), aCI.m_colName, aCI.m_className);
						qfprintf(fClassIdc, "				if (vtblName != \"\")\n");
						qfprintf(fClassIdc, "				{\n");
						qfprintf(fClassIdc, "					ea = LocByName(vtblName);\n");
						qfprintf(fClassIdc, "					if (ea == BADADDR)\n");
						qfprintf(fClassIdc, "					{\n");
						qfprintf(fClassIdc, "						Message(\"No label found for '%%s'\\n\", vtblName);\n");
						qfprintf(fClassIdc, "					}\n");
						qfprintf(fClassIdc, "					else\n");
						qfprintf(fClassIdc, "					{\n");
						qfprintf(fClassIdc, "						Jump(ea);\n");
						qfprintf(fClassIdc, "						Message(\"Working on class %%s having %%d virtual members from a total of %%d\\n\", vtblName, %d, %d);\n", nameCount, aML.size());

						UINT skipped = 0;
						if (strlen(aCI.m_colName))
							for (UINT j = 0; j < aML.size(); j++)
							{
								vftable::EntryInfo e = aML[j];
								if (!e.IsDefault() && !e.IsIdentical() && !e.IsInherited())
								{
									if (skipped)
										qfprintf(fClassIdc, "						ea = ea + pointerSize*%d;\n", skipped);
									qfprintf(fClassIdc, "						ea = DoFunc(ea, \"%s\", \"%s\");\n", e.isOutOfHierarchy ? "" : e.fullName.c_str(), e.comment.c_str());
									skipped = 0;
								}
								else
									skipped++;
							}
						// End the class in IDC script
						qfprintf(fClassIdc, "					}\n");
						qfprintf(fClassIdc, "				}\n");
						qfprintf(fClassIdc, "\n");
					}
				}
			}
		}

		// Ending of IDC main func
		qfprintf(fClassIdc, "		}\n");
		qfprintf(fClassIdc, "\n");

		// include manual definitions that cannot or should not be found in file.
		::qsnprintf(szClassExport, (MAXSTR - 1), "#include \".%s.h\"", DatabaseName);
		qfprintf(fClassIncH, "%s\n\n", szClassExport);

		for (UINT i = 0; i < RTTI::classInherit.size(); i++)
		{
			if (0 == i % 100)
				msgR("\t\t%35s Class:\t% 7d of % 7d\n", "Dump Classes to C include:", i + 1, RTTI::classList.size());

			UINT index = RTTI::classInherit[i].index;
			RTTI::classInfo aCI = RTTI::classList[index];
			vftable::VFMemberList aML = RTTI::vfTableList[index];
			bool isTemplate = aCI.m_templateInfo.m_template;
			//if (/*0 == strstr(aCI.m_classname, "::") &&*/ !isTemplate)
			{
				char varName[MAXSTR];
				char szTemplate[MAXSTR] = "template<";
				UINT size = aCI.m_bcdlist.size();
				qfprintf(fClassIncH, "//class %s\n", aCI.m_className);
				qfprintf(fClassIncH, "//\t%s\n", RTTI::classInherit[i].classes.c_str());
				qfprintf(fClassIncH, "struct __cppobj __declspec(align(%d)) %s\n", sizeof(ea_t), aCI.m_cTypeName);
				qfprintf(fClassIncH, "%s\n", "{");
				UINT parentCount = aCI.m_parents.size();
				UINT parentsSize = 0;
				for (UINT j = 0; j < parentCount; j++)
				{
					//msgR("\t\tDump Classes to C include:\t% 7d of % 7d %d '%s' :: '%s' \n", i + 1, RTTI::classList.size(), j, aCI.m_className, aCI.m_bcdlist[j].m_name);
					RTTI::classInfo* ci = &RTTI::classList[aCI.m_parents[j]];
					if (ci)
					{
						_itoa(j, varName, 10);
						qfprintf(fClassIncH, "\t%s\tbaseClass%s;	// %04X \n", ci->m_cTypeName, j > 0 ? varName : "", parentsSize);
					}
					else
						msgR("\t\tDump Classes to C include:\t% 7d of % 7d '%s'(%d) :: '%s' not found **\n", i + 1, RTTI::classList.size(), aCI.m_className, j, aCI.m_bcdlist[j].m_name);
					if (ci && ci->m_sizeFound)
						parentsSize += ci->m_size;
					else
						parentsSize += sizeof(ea_t);	// dummy value
				}
				//msgR("\t\tDump Classes to C include:\t% 7d of % 7d '%s'\n", i + 1, RTTI::classList.size(), aCI.m_className);
				dumpClassMembers(fClassIncH, aCI, aML, false, false);
				qfprintf(fClassIncH, "};\t//\t%04X\n\n", aCI.m_size);
			}
		}

		for (UINT i = 0; i < RTTI::classList.size(); i++)
		{
			if (0 == i % 100)
				msgR("\t\t%35s Class:\t% 7d of % 7d\n", "Export classes:", i + 1, RTTI::classList.size());
			//if (i > 30) break;

			//msgR("\t\tClasses:\t%d '%s'\n", i, RTTI::classList[i].m_classname);

			UINT parentCount = RTTI::classList[i].m_numBaseClasses;

			UINT iCount = (RTTI::classList[i].m_end - RTTI::classList[i].m_start) / sizeof(ea_t);
			qfprintf(fClass, "%d;\"%s\";\"%s\";" EAFORMAT ";" EAFORMAT ";" EAFORMAT ";" EAFORMAT ";%d;%d;%d;%d;%d\n", i, RTTI::classList[i].m_className,
				RTTI::classList[i].m_colName, RTTI::classList[i].m_vft, RTTI::classList[i].m_col, RTTI::classList[i].m_start, RTTI::classList[i].m_end, iCount,
				parentCount, RTTI::classList[i].m_baseClassIndex, RTTI::classList[i].m_templateInfo.m_template, RTTI::classList[i].m_templateInfo.m_templateTypeCount);
			//msgR("\t\tClasses:\t%d '%s' from '%s' and '%s'\n", i, szClassDef, szClass, RTTI::classList[i].m_classname);

			for (UINT j = parentCount - 1; j > 0; j--)
			{
				UINT k = j + RTTI::classList[i].m_baseClassIndex;
				if (k < RTTI::classList[i].m_bcdlist.size())
				{
					char plainName[MAXSTR];
					getPlainTypeName(RTTI::classList[i].m_bcdlist[k].m_name, plainName);
					qfprintf(fClassHierarchy, "%d;%d;\"%s\";\"%s\";%08X\n", i, j, plainName, RTTI::classList[i].m_bcdlist[k].m_name, (UINT32)RTTI::classList[i].m_bcdlist[k].m_attribute);
				}
			}

			UINT iIndex = 0;
			for (ea_t eaAddress = RTTI::classList[i].m_start; eaAddress < RTTI::classList[i].m_end; eaAddress += sizeof(ea_t)) {
				char memberName[MAXSTR] = "";
				ea_t eaMember = vftable::getMemberName(memberName, eaAddress);
				if (BADADDR != eaMember)
				{
					qfprintf(fClassMembers, "%d;%d;\"%s\";" EAFORMAT ";" EAFORMAT "\n", i, iIndex, memberName, eaAddress, eaMember);
				}
				iIndex++;
			}
			//msgR("\t\tClasses:\t%d '%s' from '%s'\n", i, szClassDef, szClass);
		}
	}
#ifndef __DEBUG
	CATCH()
#endif
		return(FALSE);
}

static BOOL dumpFuncs()
{
#ifndef __DEBUG
	try
#endif
	{
		for (UINT i = 0; i < RTTI::classPKeys.size(); i++)
		{
			if (0 == i % 100)
				msgR("\t\t%35s Funcs:\t% 7d of % 7d\n", "Dump funcs called from classes:", i + 1, RTTI::classList.size());

			UINT index = RTTI::classPKeys[i].index;
			RTTI::classInfo aCI = RTTI::classList[index];
			vftable::VFMemberList aML = RTTI::vfTableList[index];
			//::qsnprintf(szClassExport, MAXSTR - 1, "//\txclass '%s' vft:" EAFORMAT, aCI.m_className, aCI.m_vft);
			//qfprintf(fClassIncTemp, "%s\n", szClassExport);
			for (UINT m = 0; m < aML.size(); m++)
			{
				strcpy_s(THEprefix, "  ");
				//::qsnprintf(szClassExport, MAXSTR - 1, "//\t%sclass '%s' member I:%d " EAFORMAT, THEprefix, aCI.m_className, m, aML[m].member);
				//qfprintf(fClassIncTemp, "%s\n", szClassExport);
				char funcFromName[MAXSTR] = "";
				func_t* funcFrom = get_func(aML[m].member);
				if (funcFrom)
					LookupFuncFromName(funcFrom, index, 0, funcFromName, fClassIncTemp);
			}
		}

		UINT fq = get_func_qty();
		for (UINT index = 0; index < fq; index++)
		{
			if (0 == index % 100)
				msgR("\t\t%35s Funcs:\t% 7d of % 7d\n", "Looking for xref to functions:", index + 1, fq);

			strcpy_s(THEprefix, "  ");
			char funcFromName[MAXSTR] = "";
			func_t* funcTo = getn_func(index);
			if (funcTo)
				/*if (*/LookupFuncToName(funcTo, ++funcIndex, 0, funcFromName, fClassIncTemp)/*)
					qfprintf(fClassIncTemp, "\n")*/;
		}
	}
#ifndef __DEBUG
	CATCH()
#endif

		return(FALSE);
}

// ================================================================================================

// Gather RTTI data
static BOOL getRttiData(SegSelect::segments *segList)
{
    // Free RTTI working data on return
    struct OnReturn  { ~OnReturn() { RTTI::freeWorkingData(); }; } onReturn;

    try
    {
        // ==== Locate __type_info_root_node
        BOOL aborted = FALSE;

        // ==== Find and process Complete Object Locators (COL)
        msg("\nScanning for for RTTI Complete Object Locators..\n");
		msg("-------------------------------------------------\n");

        if(findCols(segList))
            return(TRUE);
        // typeDescList = TDs left that don't have a COL reference
        // colList = Located COLs

        // ==== Find and process vftables
        msg("\nScanning for Virtual Function Tables..\n");
		msg("-------------------------------------------------\n");

        if(findVftables(segList))
			return(TRUE);
        // colList = COLs left that don't have a vft reference

        // Could use the unlocated ref lists typeDescList & colList around for possible separate listing, etc.
        // They get cleaned up on return of this function anyhow.

		if (!optionClean && !optionFullClear && OpenFiles())
#ifndef __DEBUG
			try
#endif
		{
			msg("\nDumping vftables.\n");
			if (dumpVftables())
				return(TRUE);

			// ==== Find and process vftables
			msg("\nScanning for BS.\n");
			getBSData(Database, fileList[7].m_file);

			if (dumpFuncs())
				return(TRUE);

			CloseFiles();
		}
#ifndef __DEBUG
		catch (...)
		{
			CloseFiles();
			msgR("** Exception in %s()! ***\n", __FUNCTION__);
		}
#endif
	}
    CATCH()

    return(FALSE);
}


// ================================================================================================

static char _comment[] = "Class Informer: Locates and fixes C++ Run Time Type class and structure information.";
static char _help[] = "";
#ifdef __EA64__
static char _name[] = "Class Informer modified for B. x64 games";
#else
static char _name[] = "Class Informer modified for B. x32 games";
#endif

// Plug-in description block
__declspec(dllexport) plugin_t PLUGIN =
{
	IDP_INTERFACE_VERSION,	// IDA version plug-in is written for
	PLUGIN_PROC,            // Plug-in flags
	init,	            // Initialization function
	term,	            // Clean-up function
	run,	            // Main plug-in body
	_comment,	        // Comment
	_help,	            // Help
	_name,	            // Plug-in name shown in Edit->Plugins menu
	NULL	            // Hot key to run the plug-in
};
