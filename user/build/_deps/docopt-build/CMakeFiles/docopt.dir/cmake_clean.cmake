file(REMOVE_RECURSE
  "libdocopt.pdb"
  "libdocopt.so"
  "libdocopt.so.0"
  "libdocopt.so.0.6.2"
)

# Per-language clean rules from dependency scanning.
foreach(lang CXX)
  include(CMakeFiles/docopt.dir/cmake_clean_${lang}.cmake OPTIONAL)
endforeach()
