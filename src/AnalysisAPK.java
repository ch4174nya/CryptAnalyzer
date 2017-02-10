import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;


/* import necessary soot packages */
import soot.*;
import soot.jimple.toolkits.callgraph.CallGraph;
import soot.options.Options;
     
public class AnalysisAPK {
	public static File logFile;
	//public static FileWriter writer;
	public static CallGraph cg;
 	private final static String androidJAR = "android.jar";
 	
 	private final static String pathToAPK = "/home/chaitanya/Workspace/CryptAnalyzer/APKsToTest/";
 	private final static String pathToJARs = "/home/chaitanya/Workspace/CryptAnalyzer/AdditionalJars";
 	private final static String pathToAndroidJARS = "/home/chaitanya/Workspace/CryptAnalyzer/lib/AndroidJars";
 			//Alter these if working in a different workspace
    private static String apk ;
    		 
    public static void main(String[] args) {
    	/*
    	 * Checking arguments
    	 * (deployment phase)
    	 */
    	if(args.length == 0){
    		System.err.println("Usage: <someAPK.apk>");
    		System.err.println("Make sure the apk is in the APKsToTest directory");
    		System.exit(0);
    	}
    	
    	if(!(args[0].endsWith(".apk"))){
    		System.err.println("Usage: <someAPK.apk>");
    		System.exit(0);
    	}
    	
  
    	
    	apk = args[0];//"TelegramMessenger.apk"
		System.out.println(apk+" being analyzed."
				+ "\n Analysis involves 2 steps:"
				+ "\n1. Taint analysis using previously defined sources and sinks "
				+ "\n2. Anaylisis of Intermediate Representation to check and log violation of rules."
				+ "\n\n RULES:"
				+ "a. Modes used should not be ECB"
				+ "b. Static Initialization Vectors (IVs) shouldn’t be used"
				+ "c. Constant encryption keys shouldn’t be used"
				+ "d. Constant salts shouldn’t be used"
				+ "e. Password Based Encryption should make use of at least 1000 iterations"
				+ "f. Secure Random shouldn’t be statically seeded");
    	
    	runTaintAnalysis(apk);

    	simpleRuleAnalysis(args);
    	
    	//Post-analysis--- compiling results
    	if(InvokeStaticInstrumenter.flag==0){
      	  try {
				FileWriter writer = new FileWriter(logFile);
				writer.write("None of the said violations found.");
				writer.flush();
				writer.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
        }

        }

	private static void simpleRuleAnalysis(String[] commandLineArgs) {
    	List<String> sootArgs = new ArrayList<String>(Arrays.asList(commandLineArgs));
    	System.out.println("=========================================================================================================================");
    	System.out.println("=========================================================================================================================");
    	System.out.println("=========================================Analyzing the apk for Rules now=================================================");
    	System.out.println("=========================================================================================================================");
    	System.out.println("=========================================================================================================================");
  	    
          Options .v().set_soot_classpath(
        		  pathToJARs+"android.jar;"+
        		  /*pathToJARs+"ant-1.7.1.jar;"+
        		  pathToJARs+"httpcore-4.0.1.jar;"+
        		  pathToJARs+"paranamer-2.3.jar;"+
        		  pathToJARs+"mail-1.4.1.jar;"+
        		  pathToJARs+"joda-time-1.6.jar;"+
        		  pathToJARs+"JtAdTag-2.5.0.0.jar;"+
        		  pathToJARs+"GoogleAdMobAdsSdk-6.3.0.jar;"+
        		  pathToJARs+"javax.jms-3.1.2.2.jar;"+
        		  pathToJARs+"mobclix-4.0.3.jar;"+*/

        		  "/usr/local/java/jdk1.8.0_102/jre/lib/rt.jar;/home/chaitanya/Workspace");
          
          Options .v().set_process_dir(Collections.singletonList(pathToAPK+apk));
          
          Options .v().set_force_android_jar(androidJAR);
          Options.v().allow_phantom_refs();
          
          sootArgs.add(0, "-keep-line-number");
          
          Options.v().set_output_dir("/home/chaitanya/Workspace/CryptAnalyzer/sootOutput/Jimples");
          
    	  Options.v().set_output_format(Options.output_format_jimple);
	  
    	  Options.v().set_src_prec(Options.src_prec_apk);
    	
    	  System.out.println(Options.v().android_jars());
    	  
    	  
    	   // Initializing the log file, to log reports into it
    	   
    	  new File("./Logs").mkdir();
    	  logFile = new File("./Logs/Log_"+apk+"_.txt");
    	  
           //add a phase to transformer pack by call Pack.add 
          Pack jtp = PackManager.v().getPack("jtp");
          jtp.add(new Transform("jtp.instrumenter", new InvokeStaticInstrumenter()));
          
          /*
           * Give control to Soot to process all options,InvokeStaticInstrumenter.internalTransform will get called.
           */
          soot.Main.main(sootArgs.toArray(commandLineArgs));
	}

	private static void runTaintAnalysis(String apkToAnalyze) {
    	//Carrying out the taint analysis, specific for the salt and key rules
    	String[] taintArgs = {pathToAPK+apkToAnalyze, pathToAndroidJARS};
    	try {
			TaintAnalysis.check(taintArgs);	
		} catch (IOException | InterruptedException e1) {
			e1.printStackTrace();
		}
		
	}
}