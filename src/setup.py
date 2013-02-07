from distutils.core import setup
from distutils.extension import Extension

setup(name="PackageName",
    ext_modules=[
        Extension("pyfiresql", ["wrapper.cc"],
        libraries = ["boost_python"])
    ])

