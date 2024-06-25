// The following ifdef block is the standard way of creating macros which make exporting
// from a DLL simpler. All files within this DLL are compiled with the DILITHIUMSTRING_EXPORTS
// symbol defined on the command line. This symbol should not be defined on any project
// that uses this DLL. This way any other project whose source files include this file see
// DILITHIUMSTRING_API functions as being imported from a DLL, whereas this DLL sees symbols
// defined with this macro as being exported.
#ifdef DILITHIUMSTRING_EXPORTS
#define DILITHIUMSTRING_API __declspec(dllexport)
#else
#define DILITHIUMSTRING_API __declspec(dllimport)
#endif

// This class is exported from the dll
class DILITHIUMSTRING_API Cdilithiumstring {
public:
	Cdilithiumstring(void);
	// TODO: add your methods here.
};

extern DILITHIUMSTRING_API int ndilithiumstring;

DILITHIUMSTRING_API int fndilithiumstring(void);
