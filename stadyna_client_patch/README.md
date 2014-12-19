##StaDynA client patch

StaDynA requires modification of the Android operating system to have a
possibility to intercept dynamic code updates calls and pass the information 
about the parameters to the StaDynA server.

Our patch for the StaDynA client has been developed as a modification of the 
Android OS version 4.1.2 and tested on Google Nexus S device.

The folder *patch* contains the modified files. To apply the patch, at
first you need to initialize your environment to be able to work with AOSP as
described [here](http://source.android.com/source/building.html). After that you
need to download the code of the branch android-4.1.2_r1 and copy the files in
folder *patch* to the appropriate location (you need to substitute files in 
dalvik/ and libcore/ subfolders).

The modified files are listed in the file modified_files.txt.

Inherently, the project has been named "SECCON", thus, some files and the
modified pieces of code are highlighted with this name.
