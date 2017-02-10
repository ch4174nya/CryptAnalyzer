## Getting started
* AnalysisAPK.java:
	- the main class, sets up the configuration parameters, takes in the APK name as *someApp.apk* as commandline arguments
	- the apk file must reside in the APKsToTest directory, present in the root directory of the project 
* InvokeStaticInstrumenter.java
	- a helper class
* TaintAnalysis.java
	- carries out the taint analysis from predefined sources to sink
	- necessary to check if constant salts have been used
    
