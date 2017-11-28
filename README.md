osquery extension that queries https://github.com/duo-labs/EFIgy

Built as an example of an osquery-go plugin and for discussion of a similar pull request in osquery core: https://github.com/facebook/osquery/pull/3962
More documentation available in the osquery-go [readme](https://github.com/kolide/osquery-go#using-the-library) and osquery [wiki](https://osquery.readthedocs.io/en/latest/development/osquery-sdk/) page on extensions.

# Install

```
git clone git@github.com:groob/osquery-effigy.git $GOPATH/src/github.com/groob/osquery-effigy 
cd $GOPATH/src/github.com/groob/osquery-effigy
make deps
make build
```

# Usage

```
osqueryi --nodisable_extensions
osquery> select value from osquery_flags where name = 'extensions_socket';
+---------------------------------+
| value                           |
+---------------------------------+
| /Users/victor/.osquery/shell.em |
+---------------------------------+

./build/darwin/effigy.ext -socket /Users/victor/.osquery/shell.em

osquery> select * from effigy;
+--------------------+-----------------+--------------------+-------------------+------------+-------------------+---------------------+--------------+---------------------+
| latest_efi_version | efi_version     | efi_version_status | latest_os_version | os_version | os_version_status | latest_build_number | build_number | build_number_status |
+--------------------+-----------------+--------------------+-------------------+------------+-------------------+---------------------+--------------+---------------------+
| MP61.0120.B00      | MBP132.0226.B25 | success            | 10.13.1           | 10.13.1    | success           | 17B48               | 17B48        | success             |
+--------------------+-----------------+--------------------+-------------------+------------+-------------------+---------------------+--------------+---------------------+
```
