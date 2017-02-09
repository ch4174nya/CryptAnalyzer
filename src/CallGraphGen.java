import java.io.IOException;
import java.util.Collections;

import org.xmlpull.v1.XmlPullParserException;

import soot.PackManager;
import soot.Scene;
import soot.SootMethod;
import soot.jimple.infoflow.android.SetupApplication;
import soot.jimple.toolkits.callgraph.CallGraph;
import soot.options.Options;

/*
 * Class to generate a callgraph on input APK;
 * Dependencies: soot-infoflow and soot-infoflow-android projects
 * (Essentially builds a graph the way FlowDroid builds it-by creating a dummy main method,
 * as Android code doesn't have a main method.
 * Found @: https://mailman.cs.mcgill.ca/pipermail/soot-list/2014-June/006834.html
 */

public class CallGraphGen {
	public static CallGraph cg;
	private final static String pathToAPK = "/home/chaitanya/Workspace/CryptAnalyzer/APKsToTest/";
 	public static void generateGraph(String apk){
		apk = pathToAPK+apk;
		SetupApplication app = new SetupApplication("/home/chaitanya/Workspace/CryptAnalyzer/lib/AndroidJars",
				apk);		
		try {
			app.calculateSourcesSinksEntrypoints("SourcesAndSinks.txt");
		} catch (IOException | XmlPullParserException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		soot.G.reset();
		
		Options.v().set_src_prec(Options.src_prec_apk);
		Options.v().set_process_dir(Collections.singletonList(apk));
		Options.v().set_android_jars("/home/chaitanya/Workspace/CryptAnalyzer/lib/AndroidJars");
		Options.v().set_whole_program(true);
		Options.v().set_allow_phantom_refs(true);
		Options.v().set_output_format(Options.output_format_jimple);
		Options.v().setPhaseOption("cg.spark", "on");

		Scene.v().loadNecessaryClasses();
		
		SootMethod entryPoint = app.getEntryPointCreator().createDummyMain();
		
		Options.v().set_main_class(entryPoint.getSignature());
		
		Scene.v().setEntryPoints(Collections.singletonList(entryPoint));
		
		//System.out.println(entryPoint.getActiveBody());
		
		PackManager.v().runPacks();
		
		cg = Scene.v().getCallGraph();
		System.out.println("CallGraph generated with size:" + Scene.v().getCallGraph().size());		
		
		soot.G.reset();	//clearing up for the next analysis to take place
	}
}