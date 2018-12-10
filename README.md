# kt-semantic-code-search
Kestrel Technology tool that implements machine learning techniques to
perform semantic code search on java byte code

### system requirements

- requires python libraries: numpy, scipy, scikit-learn

### quick start

- set PYTHONPATH  (adjust for local path to kt-semantic-code-search):
  ```
  export PYTHONPATH=$HOME/kt-semantic-code-search
  ```

- generate features (invoke from scs/jbc/cmdline/generate directory):
  ```
  python chj_generatefeatures.py {path to directory with jarfiles} {path
  to save features}
  ```
  example:
  ```
  python chj_generate_features.py $HOME/jardir $HOME/features
  ```
 
- index features (invoke from scs/jbc/cmdline/algorithms directory):
  ```
  python chj_index_features.py {path to features} {path to save indexed features}
  ```
  This step creates a jar file with indexed features that has the same
  name as the basename of the path to save indexed features, and is
  saved in the same directory. This jar file is used for the
  similarity search (for the example the indexed features jar file
  would be $HOME/indexedfeatures.jar)

- find methods that have high similarity to the features specified in
  a pattern file (example pattern files are provided in the examplepatterns
  directory):
  ```
  python chj_find_similar.py {name of indexed features jar file} {name of
  pattern file}
  ```
  example:
  ```
  python chj_findsimilar.py $HOME/indexedfeatures.jar dfactorial.json
  ```
  The pattern file dfactorial.json file is taken from the default
  directory scs/jbcdata/algorithms/queries, which has a few more
  example pattern files;

- or use the default indexed features file provided for search for algorithms:
  ```
  python chj_findsimilar.py xindexedfeatures_alg.jar dfactorial.json

	Loading corpus ...
	Postings files loaded/not loaded: 216/5613 (  3.7% loaded)
	Completed in 3.007449150085449 secs


	Constructing the query matrices ...
	Creating a 531376 by 4 matrix
	Completed in 2.8567280769348145 secs


	Term weights based on their prevalence in the corpus:
		8.523744813714664   x := 1.0             (assigns)
		9.892767588325894   x := (x * x)         (inloop_assigns)
		10.312026018566394  x := (x + 1.0)       (inloop_assigns)
		7.256649996251561   (D)D                 (signatures)


	Most similar methods:
	0.9911839536051237       : cern.jet.stat.Gamma.gamma(D)D                      (colt-1.2.0.jar)
	0.9911839536051237       : cern.jet.stat.Gamma.logGamma(D)D                   (colt-1.2.0.jar)
	0.9911839536051237       : cern.jet.random.Fun.logGamma(D)D                   (colt-1.2.0.jar)
	0.9911839536051237       : cern.jet.stat.tdouble.Gamma.logGamma(D)D           (parallelcolt-0.10.1.jar)
	0.9911839536051237       : cern.jet.random.tdouble.Fun.logGamma(D)D           (parallelcolt-0.10.1.jar)
	0.9911839536051237       : cern.jet.stat.tdouble.Gamma.gamma(D)D              (parallelcolt-0.10.1.jar)
	0.9137205268502868       : cern.jet.math.Bessel.kn(I,D)D                      (colt-1.2.0.jar)
	0.9137205268502868       : cern.jet.stat.tdouble.Gamma.incompleteGammaComplement(D,D)D (parallelcolt-0.10.1.jar)
	0.9137205268502868       : cern.jet.math.tdouble.Bessel.kn(I,D)D              (parallelcolt-0.10.1.jar)
	0.9137205268502868       : cern.jet.stat.Gamma.incompleteGammaComplement(D,D)D (colt-1.2.0.jar)
	0.8298779477463764       : flanagan.math.PsRandom.nextPoissonian(D)D          (flanagan.jar)
	0.7870456046552124       : cern.jet.stat.Gamma.powerSeries(D,D,D)D            (colt-1.2.0.jar)
	0.7870456046552124       : cern.jet.stat.tdouble.Gamma.powerSeries(D,D,D)D    (parallelcolt-0.10.1.jar)
	0.7337174995335101       : cern.jet.stat.Gamma.incompleteGamma(D,D)D          (colt-1.2.0.jar)
	0.7337174995335101       : flanagan.math.FourierTransform.lowPassFilter(D)[D  (flanagan.jar)
	0.7337174995335101       : cern.jet.math.tfloat.FloatArithmetic.binomial(F,L)F (parallelcolt-0.10.1.jar)
	0.7337174995335101       : cern.jet.stat.Gamma.incompleteBetaFraction2(D,D,D)D (colt-1.2.0.jar)
	0.7337174995335101       : flanagan.analysis.Stat.poissonRandCalc(Random,D,I)[D (flanagan.jar)
	0.7337174995335101       : cern.jet.stat.tdouble.Gamma.incompleteGamma(D,D)D  (parallelcolt-0.10.1.jar)
	0.7337174995335101       : cern.jet.stat.tdouble.Gamma.incompleteBetaFraction1(D,D,D)D (parallelcolt-0.10.1.jar)
	0.7337174995335101       : cern.jet.math.tdouble.DoubleArithmetic.binomial(D,L)D (parallelcolt-0.10.1.jar)
	0.7337174995335101       : cern.jet.math.Arithmetic.binomial(D,L)D            (colt-1.2.0.jar)

	0.7337174995335101       : org.apache.commons.math.special.Gamma.regularizedGammaP(D,D,D,I)D (commons-math-2.2.jar)
	0.7337174995335101       : cern.jet.stat.Gamma.incompleteBetaFraction1(D,D,D)D (colt-1.2.0.jar)
	0.7337174995335101       : cern.jet.stat.tdouble.Gamma.incompleteBetaFraction2(D,D,D)D (parallelcolt-0.10.1.jar)
	0.7337174995335101       : flanagan.math.PsRandom.poissonianArray(D,I)[D      (flanagan.jar)
	0.717385954101496        : org.elasticsearch.search.aggregations.pipeline.movavg.SimulatedAnealingMinimizer.minimize(MovAvgModel,EvictingQueue,[D)MovAvgModel (elasticsearch-6.3.2.jar)
	0.717385954101496        : org.apache.commons.math.linear.EigenDecompositionImpl.getDeterminant()D (commons-math-2.2.jar)
	0.717385954101496        : org.apache.commons.math.optimization.fitting.PolynomialFitter$ParametricPolynomial.gradient(D,[D)[D (commons-math-2.2.jar)
	0.717385954101496        : cern.jet.stat.tfloat.FloatDescriptive.moment(I,F,I,[F)F (parallelcolt-0.10.1.jar)
	```
	- Another script is provided to provide the expressions of interest directly on the commandline:
	```
	python chj_search.py xindexedfeatures_alg.jar --inloop_conditions "(i > 5)"
	
	Loading the corpus ...
	Postings files loaded/not loaded: 8/1935 (  0.4% loaded)
	Completed in 2.691309928894043 secs


	Constructing the query matrices ...
	Creating a 531376 by 1 matrix
	Completed in 0.9759008884429932 secs


	Term weights based on their prevalence in the corpus:
		11.544169699859028  (i > 5)              (inloop_conditions)


	Most similar methods:
	1.0: org.apache.commons.compress.compressors.gzip.GzipUtils.isCompressedFilename(String)Z (apache-jakarta-commons-compress.jar)
	1.0: org.h2.util.StringUtils.<clinit>()V (bitcoinj-core-0.14.7-bundled.jar)
	1.0: org.spongycastle.pqc.math.linearalgebra.GF2nPolynomialField.<init>(I,GF2Polynomial)V (bitcoinj-core-0.14.7-bundled.jar)
	1.0: org.apache.commons.compress.compressors.bzip2.BZip2Utils.isCompressedFilename(String)Z (apache-jakarta-commons-compress.jar)
	1.0: cern.jet.random.tdouble.PoissonSlow.logGamma(D)D (parallelcolt-0.10.1.jar)
	1.0: cern.jet.random.tdouble.Fun.bessel2_fkt(D,D)D (parallelcolt-0.10.1.jar)
	1.0: org.apache.commons.compress.compressors.bzip2.BZip2Utils.getUncompressedFilename(String)String (apache-jakarta-commons-compress.jar)
	1.0: org.bouncycastle.pqc.math.linearalgebra.GF2nPolynomialField.<init>(I,SecureRandom,GF2Polynomial)V (bcprov-jdk15on-1.54.jar)
	1.0: cern.jet.random.PoissonSlow.logGamma(D)D (colt-1.2.0.jar)
	1.0: cern.jet.random.Fun.bessel2_fkt(D,D)D (colt-1.2.0.jar)
	1.0: org.apache.commons.compress.compressors.gzip.GzipUtils.getCompressedFilename(String)String (apache-jakarta-commons-compress.jar)
	1.0: com.mysql.jdbc.StringUtils.indexOfNextChar(I,I,String,String,String,Set)I (bitcoinj-core-0.14.7-bundled.jar)
	1.0: org.apache.commons.compress.compressors.gzip.GzipUtils.getUncompressedFilename(String)String (apache-jakarta-commons-compress.jar)
	```
