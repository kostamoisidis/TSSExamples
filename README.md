# TSSExamples
This C# app implements some examples of TPM usage with Microsoft.TSS Library.

Main focus is made on preserving Persistent key handles through application rerun. Used code snippets can found in [TSS.MSR](https://github.com/microsoft/TSS.MSR) repository.

TSS.MST uses simlated TPM 2.0 chip and connects to it over TCP. Download **TSS.MSR: The TPM Software Stack from Microsoft Research** binary [here](https://www.microsoft.com/en-us/download/details.aspx?id=52507).

## Testing steps:
1, start the `simulator` binary.  
2, run the app and go through all the steps ( 0, 1, (2), 3, 4, 5, 6, 7, 8 )  
3, relaunch the app with the `simulator` still runing the same session and go with steps 0, 6, 7, 8
NOTE: Reruing the `simulator` will cause change in TMP seed resulting in new primary key.


