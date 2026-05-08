from setuptools import setup, find_packages

setup(
    name="archive_triangulator",
    version="1.0.0",
    description="Three-way archive comparison tool for documenting suspected post-hoc alteration of web archive records",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    author="PolicyWatch / Operation Gridlack",
    license="AGPL-3.0",
    packages=find_packages(),
    py_modules=["src.triangulator", "src.diff_runs", "src.verify_run"],
    install_requires=["requests>=2.31.0", "urllib3>=2.0.0"],
    python_requires=">=3.11",
    entry_points={
        "console_scripts": [
            "archive_triangulator=src.triangulator:main",
            "diff_runs=src.diff_runs:main",
            "verify_run=src.verify_run:main",
        ],
    },
)
