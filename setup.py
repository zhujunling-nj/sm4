''' setup tools '''
import sys
from setuptools import setup, Extension

def main():
    ''' Entry of script '''
    link_args = ['-s'] if sys.platform != 'win32' else []
    setup(name="sm4",
          version="1.2.0",
          description="Python interface for the sm4.",
          author="Zhu Junling",
          author_email="jl.zhu@tom.com",
          ext_modules=[Extension("_sm4",
                sources=["sm4_moudle.cpp", "sm4.cpp", "ghash.cpp"],
                extra_link_args=link_args
          )],
          py_modules=["sm4", "ghash"]
    )

if __name__ == "__main__":
    main()
