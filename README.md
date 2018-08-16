# ktjbcmlscs
Kestrel Technology tool that implements machine learning techniques to
perform semantic code search on java byte code

### system requirements

- requires python libraries: numpy, scipy, scikit-learn

### quick start

- set PYTHONPATH  (adjust for local path to ktjbcmlscs):
  ```
  export PYTHONPATH=$HOME/ktjbcmlscs
  ```

- edit jbcmlscs/util/Config.py (if necessary):
  set platform to mac or linux as appropriate

- generate features (invoke from jbcmlscs/bin directory):
  ```
  python chj_generate_features.py {path to directory with jarfiles} {path
  to save features} {path to save indexed features}
  ```
  example:
  ```
  python chj_generate_features.py $HOME/jardir $HOME/features $HOME/indexedfeatures
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
  python chj_find_similar.py $HOME/indexedfeatures.jar ../../examplepatterns/factorial.json
  ```

- or use the indexed feature file provided here:
  ```
  python chj_findsimilar.py ../../exampleindexedfeatures/indexedfeatures.jar ../../examplepatterns/factorial.json

  Loading the corpus ...
  Completed in 16.889575004577637 secs


  Constructing the query matrices ...
  Creating a 757561 by 4 matrix
  Completed in 5.439270973205566 secs


  Term weights based on their prevalence in the corpus:
    5.42833559446 i:=i (method-assignments-vmcfsi)
    7.34567860249 i:=(i * i) (method-assignments-vmcfsi)
    6.43618291375 (I)I (signatures)
    3.22202121323 loops (sizes)


  Most similar methods:
  0.964501673359: ise.antelope.tasks.Math.factorial(I)I (antelopetasks_3.5.3.jar)
  0.964501673359: ise.antelope.tasks.util.math.Math.factorial(I)I (antelopetasks_3.5.3.jar)
  0.964501673359: ucar.unidata.util.SpecialMathFunction.fac(I)I (netcdf-2.2.22.jar)
  0.844205605925: flanagan.math.Fmath.factorial(I)I (flanagan.jar)
  0.844205605925: flanagan.analysis.Stat.factorial(I)I (flanagan.jar)
  0.844205605925: org.ejml.alg.dense.misc.PermuteArray.fact(I)I (ejml-nogui.jar,ejml.jar)
  0.844205605925: com.liferay.portal.kernel.util.MathUtil.factorial(I)I (liferay-portal-service-6.1.1.jar)
  0.844205605925: org.ejml.alg.dense.misc.PermuteArray.fact(I)I (ejml-nogui.jar,ejml.jar)
  0.794168189742: cern.colt.matrix.tdcomplex.impl.DenseDComplexMatrix2D.getRealPart()Lcern/colt/matrix/tdouble/DoubleMatrix2D; (parallelcolt-0.10.1.jar)
  0.794168189742: cern.colt.matrix.tlong.impl.DenseLongMatrix2D.vectorize()Lcern/colt/matrix/tlong/LongMatrix1D; (parallelcolt-0.10.1.jar)
  .......
  ```

