# Licensed under the Apache License, Version 2.0 (the "License"); you may not
# use this file except in compliance with the License. You may obtain a copy
# of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.
"""
The ``swift-manage-shard-ranges`` tool provides commands for initiating
sharding of a container. ``swift-manage-shard-ranges`` operates directly on a
container database file.

.. note::

    ``swift-manage-shard-ranges`` must only be used on one replica of a
    container database to avoid inconsistent results. The modifications made by
    ``swift-manage-shard-ranges`` will be automatically copied to other
    replicas of the container database via normal replication processes.

There are three steps in the process of initiating sharding, each of which may
be performed in isolation or, as shown below, using a single command.

#. The ``find`` sub-command scans the container database to identify how many
   shard containers will be required and which objects they will manage. Each
   shard container manages a range of the object namespace defined by a
   ``lower`` and ``upper`` bound. The maximum number of objects to be allocated
   to each shard container is specified on the command line. For example::

    $ swift-manage-shard-ranges <path_to_db> find 500000
    Loaded db broker for AUTH_test/c1.
    [
      {
        "index": 0,
        "lower": "",
        "object_count": 500000,
        "upper": "o_01086834"
      },
      {
        "index": 1,
        "lower": "o_01086834",
        "object_count": 500000,
        "upper": "o_01586834"
      },
      {
        "index": 2,
        "lower": "o_01586834",
        "object_count": 500000,
        "upper": "o_02087570"
      },
      {
        "index": 3,
        "lower": "o_02087570",
        "object_count": 500000,
        "upper": "o_02587572"
      },
      {
        "index": 4,
        "lower": "o_02587572",
        "object_count": 500000,
        "upper": "o_03087572"
      },
      {
        "index": 5,
        "lower": "o_03087572",
        "object_count": 500000,
        "upper": "o_03587572"
      },
      {
        "index": 6,
        "lower": "o_03587572",
        "object_count": 349194,
        "upper": ""
      }
    ]
    Found 7 ranges in 4.37222s (total object count 3349194)

   This command returns a list of shard ranges each of which describes the
   namespace to be managed by a shard container. No other action is taken by
   this command and the container database is unchanged. The output may be
   redirected to a file for subsequent retrieval by the ``replace`` command.
   For example::

    $ swift-manage-shard-ranges <path_to_db> find 500000 > my_shard_ranges
    Loaded db broker for AUTH_test/c1.
    Found 7 ranges in 2.448s (total object count 3349194)

#. The ``replace`` sub-command deletes any shard ranges that might already be
   in the container database and inserts shard ranges from a given file. The
   file contents should be in the format generated by the ``find`` sub-command.
   For example::

    $ swift-manage-shard-ranges <path_to_db> replace my_shard_ranges
    Loaded db broker for AUTH_test/c1.
    No shard ranges found to delete.
    Injected 7 shard ranges.
    Run container-replicator to replicate them to other nodes.
    Use the enable sub-command to enable sharding.

   The container database is modified to store the shard ranges, but the
   container will not start sharding until sharding is enabled. The ``info``
   sub-command may be used to inspect the state of the container database at
   any point, and the ``show`` sub-command may be used to display the inserted
   shard ranges.

   Shard ranges stored in the container database may be replaced using the
   ``replace`` sub-command. This will first delete all existing shard ranges
   before storing new shard ranges. Shard ranges may also be deleted from the
   container database using the ``delete`` sub-command.

   Shard ranges should not be replaced or deleted using
   ``swift-manage-shard-ranges`` once the next step of enabling sharding has
   been taken.

#. The ``enable`` sub-command enables the container for sharding. The sharder
   daemon and/or container replicator daemon will replicate shard ranges to
   other replicas of the container DB and the sharder daemon will proceed to
   shard the container. This process may take some time depending on the size
   of the container, the number of shard ranges and the underlying hardware.

   .. note::

       Once the ``enable`` sub-command has been used there is no supported
       mechanism to revert sharding. Do not use ``swift-manage-shard-ranges``
       to make any further changes to the shard ranges in the container DB.

   For example::

    $ swift-manage-shard-ranges <path_to_db> enable
    Loaded db broker for AUTH_test/c1.
    Container moved to state 'sharding' with epoch 1525345093.22908.
    Run container-sharder on all nodes to shard the container.

   This does not shard the container - sharding is performed by the
   :ref:`sharder_daemon` - but sets the necessary state in the database for the
   daemon to subsequently start the sharding process.

   The ``epoch`` value displayed in the output is the time at which sharding
   was enabled. When the :ref:`sharder_daemon` starts sharding this container
   it creates a new container database file using the epoch in the filename to
   distinguish it from the retiring DB that is being sharded.

All three steps may be performed with one sub-command::

    $ swift-manage-shard-ranges <path_to_db> find_and_replace 500000 --enable \
--force
    Loaded db broker for AUTH_test/c1.
    No shard ranges found to delete.
    Injected 7 shard ranges.
    Run container-replicator to replicate them to other nodes.
    Container moved to state 'sharding' with epoch 1525345669.46153.
    Run container-sharder on all nodes to shard the container.

"""
from __future__ import print_function
import argparse
import json
import os.path
import sys
import time
from contextlib import contextmanager

from six.moves import input


from swift.common.utils import Timestamp, get_logger, ShardRange, readconf, \
    ShardRangeList
from swift.container.backend import ContainerBroker, UNSHARDED
from swift.container.sharder import make_shard_ranges, sharding_enabled, \
    CleavingContext, process_compactible_shard_sequences, \
    find_compactible_shard_sequences, find_overlapping_ranges, \
    find_paths, rank_paths, finalize_shrinking, DEFAULT_SHARDER_CONF, \
    ContainerSharderConf

EXIT_SUCCESS = 0
EXIT_ERROR = 1
EXIT_INVALID_ARGS = 2  # consistent with argparse exit code for invalid args
EXIT_USER_QUIT = 3

# Some CLI options derive their default values from DEFAULT_SHARDER_CONF if
# they have not been set. It is therefore important that the CLI parser
# provides None as a default so that we can detect that no value was set on the
# command line. We use this alias to act as a reminder.
USE_SHARDER_DEFAULT = object()


class ManageShardRangesException(Exception):
    pass


class GapsFoundException(ManageShardRangesException):
    pass


class InvalidStateException(ManageShardRangesException):
    pass


class InvalidSolutionException(ManageShardRangesException):
    def __init__(self, msg, acceptor_path, overlapping_donors):
        super(InvalidSolutionException, self).__init__(msg)
        self.acceptor_path = acceptor_path
        self.overlapping_donors = overlapping_donors


def _proceed(args):
    if args.dry_run:
        choice = 'no'
    elif args.yes:
        choice = 'yes'
    else:
        choice = input('Do you want to apply these changes to the container '
                       'DB? [yes/N]')
    if choice != 'yes':
        print('No changes applied')

    return choice == 'yes'


def _print_shard_range(sr, level=0):
    indent = '  ' * level
    print(indent + '%r' % sr.name)
    print(indent + '  objects: %9d, tombstones: %9d, lower: %r'
          % (sr.object_count, sr.tombstones, sr.lower_str))
    print(indent + '    state: %9s,                        upper: %r'
          % (sr.state_text, sr.upper_str))


@contextmanager
def _open_input(args):
    if args.input == '-':
        args.input = '<STDIN>'
        yield sys.stdin
    else:
        with open(args.input, 'r') as fd:
            yield fd


def _load_and_validate_shard_data(args, require_index=True):
    required_keys = ['lower', 'upper', 'object_count']
    if require_index:
        required_keys.append('index')
    try:
        with _open_input(args) as fd:
            try:
                data = json.load(fd)
                if not isinstance(data, list):
                    raise ValueError('Shard data must be a list of dicts')
                for k in required_keys:
                    for shard in data:
                        shard[k]  # trigger KeyError for missing required key
                return data
            except (TypeError, ValueError, KeyError) as err:
                print('Failed to load valid shard range data: %r' % err,
                      file=sys.stderr)
                exit(2)
    except IOError as err:
        print('Failed to open file %s: %s' % (args.input, err),
              file=sys.stderr)
        exit(2)


def _check_shard_ranges(own_shard_range, shard_ranges):
    reasons = []

    def reason(x, y):
        if x != y:
            reasons.append('%s != %s' % (x, y))

    if not shard_ranges:
        reasons.append('No shard ranges.')
    else:
        reason(own_shard_range.lower, shard_ranges[0].lower)
        reason(own_shard_range.upper, shard_ranges[-1].upper)
        for x, y in zip(shard_ranges, shard_ranges[1:]):
            reason(x.upper, y.lower)

    if reasons:
        print('WARNING: invalid shard ranges: %s.' % reasons)
        print('Aborting.')
        exit(EXIT_ERROR)


def _check_own_shard_range(broker, args):
    # TODO: this check is weak - if the shards prefix changes then we may not
    # identify a shard container. The goal is to not inadvertently create an
    # entire namespace default shard range for a shard container.
    is_shard = broker.account.startswith(args.shards_account_prefix)
    own_shard_range = broker.get_own_shard_range(no_default=is_shard)
    if not own_shard_range:
        print('WARNING: shard container missing own shard range.')
        print('Aborting.')
        exit(2)
    return own_shard_range


def _find_ranges(broker, args, status_file=None):
    start = last_report = time.time()
    limit = 5 if status_file else -1
    shard_data, last_found = broker.find_shard_ranges(
        args.rows_per_shard, limit=limit,
        minimum_shard_size=args.minimum_shard_size)
    if shard_data:
        while not last_found:
            if last_report + 10 < time.time():
                print('Found %d ranges in %gs; looking for more...' % (
                    len(shard_data), time.time() - start), file=status_file)
                last_report = time.time()
            # prefix doesn't matter since we aren't persisting it
            found_ranges = make_shard_ranges(broker, shard_data, '.shards_')
            more_shard_data, last_found = broker.find_shard_ranges(
                args.rows_per_shard, existing_ranges=found_ranges, limit=5,
                minimum_shard_size=args.minimum_shard_size)
            shard_data.extend(more_shard_data)
    return shard_data, time.time() - start


def find_ranges(broker, args):
    shard_data, delta_t = _find_ranges(broker, args, sys.stderr)
    print(json.dumps(shard_data, sort_keys=True, indent=2))
    print('Found %d ranges in %gs (total object count %s)' %
          (len(shard_data), delta_t,
           sum(r['object_count'] for r in shard_data)),
          file=sys.stderr)
    return EXIT_SUCCESS


def show_shard_ranges(broker, args):
    shard_ranges = broker.get_shard_ranges(
        includes=getattr(args, 'includes', None),
        include_deleted=getattr(args, 'include_deleted', False))
    shard_data = [dict(sr, state=sr.state_text)
                  for sr in shard_ranges]

    if not shard_data:
        print("No shard data found.", file=sys.stderr)
    elif getattr(args, 'brief', False):
        print("Existing shard ranges:", file=sys.stderr)
        print(json.dumps([(sd['lower'], sd['upper']) for sd in shard_data],
                         sort_keys=True, indent=2))
    else:
        print("Existing shard ranges:", file=sys.stderr)
        print(json.dumps(shard_data, sort_keys=True, indent=2))
    return EXIT_SUCCESS


def db_info(broker, args):
    print('Sharding enabled = %s' % sharding_enabled(broker))
    own_sr = broker.get_own_shard_range(no_default=True)
    print('Own shard range: %s' %
          (json.dumps(dict(own_sr, state=own_sr.state_text),
                      sort_keys=True, indent=2)
           if own_sr else None))
    db_state = broker.get_db_state()
    print('db_state = %s' % db_state)
    if db_state == 'sharding':
        print('Retiring db id: %s' % broker.get_brokers()[0].get_info()['id'])
        print('Cleaving context: %s' %
              json.dumps(dict(CleavingContext.load(broker)),
                         sort_keys=True, indent=2))
    print('Metadata:')
    for k, (v, t) in broker.metadata.items():
        print('  %s = %s' % (k, v))
    return EXIT_SUCCESS


def delete_shard_ranges(broker, args):
    shard_ranges = broker.get_shard_ranges()
    if not shard_ranges:
        print("No shard ranges found to delete.")
        return EXIT_SUCCESS

    while not args.force:
        print('This will delete existing %d shard ranges.' % len(shard_ranges))
        if broker.get_db_state() != UNSHARDED:
            print('WARNING: Be very cautious about deleting existing shard '
                  'ranges. Deleting all ranges in this db does not guarantee '
                  'deletion of all ranges on all replicas of the db.')
            print('  - this db is in state %s' % broker.get_db_state())
            print('  - %d existing shard ranges have started sharding' %
                  [sr.state != ShardRange.FOUND
                   for sr in shard_ranges].count(True))
        choice = input('Do you want to show the existing ranges [s], '
                       'delete the existing ranges [yes] '
                       'or quit without deleting [q]? ')
        if choice == 's':
            show_shard_ranges(broker, args)
            continue
        elif choice == 'q':
            return EXIT_USER_QUIT
        elif choice == 'yes':
            break
        else:
            print('Please make a valid choice.')
            print()

    now = Timestamp.now()
    for sr in shard_ranges:
        sr.deleted = 1
        sr.timestamp = now
    broker.merge_shard_ranges(shard_ranges)
    print('Deleted %s existing shard ranges.' % len(shard_ranges))
    return EXIT_SUCCESS


def _replace_shard_ranges(broker, args, shard_data, timeout=0):
    own_shard_range = _check_own_shard_range(broker, args)
    shard_ranges = make_shard_ranges(
        broker, shard_data, args.shards_account_prefix)
    _check_shard_ranges(own_shard_range, shard_ranges)

    if args.verbose > 0:
        print('New shard ranges to be injected:')
        print(json.dumps([dict(sr) for sr in shard_ranges],
                         sort_keys=True, indent=2))

    # Crank up the timeout in an effort to *make sure* this succeeds
    with broker.updated_timeout(max(timeout, args.replace_timeout)):
        delete_status = delete_shard_ranges(broker, args)
        if delete_status != EXIT_SUCCESS:
            return delete_status
        broker.merge_shard_ranges(shard_ranges)

    print('Injected %d shard ranges.' % len(shard_ranges))
    print('Run container-replicator to replicate them to other nodes.')
    if args.enable:
        return enable_sharding(broker, args)
    else:
        print('Use the enable sub-command to enable sharding.')
        return EXIT_SUCCESS


def replace_shard_ranges(broker, args):
    shard_data = _load_and_validate_shard_data(args)
    return _replace_shard_ranges(broker, args, shard_data)


def find_replace_shard_ranges(broker, args):
    shard_data, delta_t = _find_ranges(broker, args, sys.stdout)
    # Since we're trying to one-shot this, and the previous step probably
    # took a while, make the timeout for writing *at least* that long
    return _replace_shard_ranges(broker, args, shard_data, timeout=delta_t)


def _enable_sharding(broker, own_shard_range, args):
    if own_shard_range.update_state(ShardRange.SHARDING):
        own_shard_range.epoch = Timestamp.now()
        own_shard_range.state_timestamp = own_shard_range.epoch

    with broker.updated_timeout(args.enable_timeout):
        broker.merge_shard_ranges([own_shard_range])
        broker.update_metadata({'X-Container-Sysmeta-Sharding':
                                ('True', Timestamp.now().normal)})
    return own_shard_range


def enable_sharding(broker, args):
    own_shard_range = _check_own_shard_range(broker, args)
    _check_shard_ranges(own_shard_range, broker.get_shard_ranges())

    if own_shard_range.state == ShardRange.ACTIVE:
        own_shard_range = _enable_sharding(broker, own_shard_range, args)
        print('Container moved to state %r with epoch %s.' %
              (own_shard_range.state_text, own_shard_range.epoch.internal))
    elif own_shard_range.state == ShardRange.SHARDING:
        if own_shard_range.epoch:
            print('Container already in state %r with epoch %s.' %
                  (own_shard_range.state_text, own_shard_range.epoch.internal))
            print('No action required.')
        else:
            print('Container already in state %r but missing epoch.' %
                  own_shard_range.state_text)
            own_shard_range = _enable_sharding(broker, own_shard_range, args)
            print('Container in state %r given epoch %s.' %
                  (own_shard_range.state_text, own_shard_range.epoch.internal))
    else:
        print('WARNING: container in state %s (should be active or sharding).'
              % own_shard_range.state_text)
        print('Aborting.')
        return EXIT_ERROR

    print('Run container-sharder on all nodes to shard the container.')
    return EXIT_SUCCESS


def compact_shard_ranges(broker, args):
    if not broker.is_root_container():
        print('WARNING: Shard containers cannot be compacted.')
        print('This command should be used on a root container.')
        return EXIT_ERROR

    if not broker.is_sharded():
        print('WARNING: Container is not yet sharded so cannot be compacted.')
        return EXIT_ERROR

    shard_ranges = broker.get_shard_ranges()
    if find_overlapping_ranges([sr for sr in shard_ranges if
                                sr.state != ShardRange.SHRINKING]):
        print('WARNING: Container has overlapping shard ranges so cannot be '
              'compacted.')
        return EXIT_ERROR

    compactible = find_compactible_shard_sequences(broker,
                                                   args.shrink_threshold,
                                                   args.expansion_limit,
                                                   args.max_shrinking,
                                                   args.max_expanding)
    if not compactible:
        print('No shards identified for compaction.')
        return EXIT_SUCCESS

    for sequence in compactible:
        if sequence[-1].state not in (ShardRange.ACTIVE, ShardRange.SHARDED):
            print('ERROR: acceptor not in correct state: %s' % sequence[-1],
                  file=sys.stderr)
            return EXIT_ERROR

    for sequence in compactible:
        acceptor = sequence[-1]
        donors = sequence[:-1]
        print('Donor shard range(s) with total of %d rows:'
              % donors.row_count)
        for donor in donors:
            _print_shard_range(donor, level=1)
        print('can be compacted into acceptor shard range:')
        _print_shard_range(acceptor, level=1)
    print('Total of %d shard sequences identified for compaction.'
          % len(compactible))
    print('Once applied to the broker these changes will result in shard '
          'range compaction the next time the sharder runs.')

    if not _proceed(args):
        return EXIT_USER_QUIT

    process_compactible_shard_sequences(broker, compactible)
    print('Updated %s shard sequences for compaction.' % len(compactible))
    print('Run container-replicator to replicate the changes to other '
          'nodes.')
    print('Run container-sharder on all nodes to compact shards.')
    return EXIT_SUCCESS


def _find_overlapping_donors(shard_ranges, own_sr, args):
    shard_ranges = ShardRangeList(shard_ranges)
    if ShardRange.SHARDING in shard_ranges.states:
        # This may be over-cautious, but for now we'll avoid dealing with
        # SHARDING shards (which by design will temporarily overlap with their
        # sub-shards) and require repair to be re-tried once sharding has
        # completed. Note that once a shard ranges moves from SHARDING to
        # SHARDED state and is deleted, some replicas of the shard may still be
        # in the process of sharding but we cannot detect that at the root.
        raise InvalidStateException('Found shard ranges in sharding state')
    if ShardRange.SHRINKING in shard_ranges.states:
        # Also stop now if there are SHRINKING shard ranges: we would need to
        # ensure that these were not chosen as acceptors, but for now it is
        # simpler to require repair to be re-tried once shrinking has
        # completes.
        raise InvalidStateException('Found shard ranges in shrinking state')

    paths = find_paths(shard_ranges)
    ranked_paths = rank_paths(paths, own_sr)
    if not (ranked_paths and ranked_paths[0].includes(own_sr)):
        # individual paths do not have gaps within them; if no path spans the
        # entire namespace then there must be a gap in the shard_ranges
        raise GapsFoundException

    # simple repair strategy: choose the highest ranked complete sequence and
    # shrink all other shard ranges into it
    acceptor_path = ranked_paths[0]
    acceptor_names = set(sr.name for sr in acceptor_path)
    overlapping_donors = ShardRangeList([sr for sr in shard_ranges
                                         if sr.name not in acceptor_names])

    # check that the solution makes sense: if the acceptor path has the most
    # progressed continuous cleaving, which has reached cleaved_upper, then we
    # don't expect any shard ranges beyond cleaved_upper to be in states
    # CLEAVED or ACTIVE, otherwise there should have been a better acceptor
    # path that reached them.
    cleaved_states = {ShardRange.CLEAVED, ShardRange.ACTIVE}
    cleaved_upper = acceptor_path.find_lower(
        lambda sr: sr.state not in cleaved_states)
    beyond_cleaved = acceptor_path.filter(marker=cleaved_upper)
    if beyond_cleaved.states.intersection(cleaved_states):
        raise InvalidSolutionException(
            'Isolated cleaved and/or active shard ranges in acceptor path',
            acceptor_path, overlapping_donors)
    beyond_cleaved = overlapping_donors.filter(marker=cleaved_upper)
    if beyond_cleaved.states.intersection(cleaved_states):
        raise InvalidSolutionException(
            'Isolated cleaved and/or active shard ranges in donor ranges',
            acceptor_path, overlapping_donors)

    return acceptor_path, overlapping_donors


def print_repair_solution(acceptor_path, overlapping_donors):
    print('Donors:')
    for donor in sorted(overlapping_donors):
        _print_shard_range(donor, level=1)
    print('Acceptors:')
    for acceptor in acceptor_path:
        _print_shard_range(acceptor, level=1)


def find_repair_solution(shard_ranges, own_sr, args):
    try:
        acceptor_path, overlapping_donors = _find_overlapping_donors(
            shard_ranges, own_sr, args)
    except GapsFoundException:
        print('Found no complete sequence of shard ranges.')
        print('Repairs necessary to fill gaps.')
        print('Gap filling not supported by this tool. No repairs performed.')
        raise
    except InvalidStateException as exc:
        print('WARNING: %s' % exc)
        print('No repairs performed.')
        raise
    except InvalidSolutionException as exc:
        print('ERROR: %s' % exc)
        print_repair_solution(exc.acceptor_path, exc.overlapping_donors)
        print('No repairs performed.')
        raise

    if not overlapping_donors:
        print('Found one complete sequence of %d shard ranges and no '
              'overlapping shard ranges.' % len(acceptor_path))
        print('No repairs necessary.')
        return None, None

    print('Repairs necessary to remove overlapping shard ranges.')
    print('Chosen a complete sequence of %d shard ranges with current total '
          'of %d object records to accept object records from %d overlapping '
          'donor shard ranges.' %
          (len(acceptor_path), acceptor_path.object_count,
           len(overlapping_donors)))
    if args.verbose:
        print_repair_solution(acceptor_path, overlapping_donors)

    print('Once applied to the broker these changes will result in:')
    print('    %d shard ranges being removed.' % len(overlapping_donors))
    print('    %d object records being moved to the chosen shard ranges.'
          % overlapping_donors.object_count)

    return acceptor_path, overlapping_donors


def repair_shard_ranges(broker, args):
    if not broker.is_root_container():
        print('WARNING: Shard containers cannot be repaired.')
        print('This command should be used on a root container.')
        return EXIT_ERROR

    shard_ranges = broker.get_shard_ranges()
    if not shard_ranges:
        print('No shards found, nothing to do.')
        return EXIT_SUCCESS

    own_sr = broker.get_own_shard_range()
    try:
        acceptor_path, overlapping_donors = find_repair_solution(
            shard_ranges, own_sr, args)
    except ManageShardRangesException:
        return EXIT_ERROR

    if not acceptor_path:
        return EXIT_SUCCESS

    if not _proceed(args):
        return EXIT_USER_QUIT

    # merge changes to the broker...
    # note: acceptors do not need to be modified since they already span the
    # complete range
    ts_now = Timestamp.now()
    finalize_shrinking(broker, [], overlapping_donors, ts_now)
    print('Updated %s donor shard ranges.' % len(overlapping_donors))
    print('Run container-replicator to replicate the changes to other nodes.')
    print('Run container-sharder on all nodes to repair shards.')
    return EXIT_SUCCESS


def analyze_shard_ranges(args):
    shard_data = _load_and_validate_shard_data(args, require_index=False)
    for data in shard_data:
        # allow for incomplete shard range data that may have been scraped from
        # swift-container-info output
        data.setdefault('epoch', None)
    shard_ranges = [ShardRange.from_dict(data) for data in shard_data]
    whole_sr = ShardRange('whole/namespace', 0)
    try:
        find_repair_solution(shard_ranges, whole_sr, args)
    except ManageShardRangesException:
        return EXIT_ERROR
    return EXIT_SUCCESS


def _positive_int(arg):
    val = int(arg)
    if val <= 0:
        raise argparse.ArgumentTypeError('must be > 0')
    return val


def _add_find_args(parser):
    parser.add_argument(
        'rows_per_shard', nargs='?', type=int, default=USE_SHARDER_DEFAULT,
        help='Target number of rows for newly created shards. '
        'Default is half of the shard_container_threshold value if that is '
        'given in a conf file specified with --config, otherwise %s.'
        % DEFAULT_SHARDER_CONF['rows_per_shard'])
    parser.add_argument(
        '--minimum-shard-size', type=_positive_int,
        default=USE_SHARDER_DEFAULT,
        help='Minimum size of the final shard range. If this is greater than '
        'one then the final shard range may be extended to more than '
        'rows_per_shard in order to avoid a further shard range with less '
        'than minimum-shard-size rows.')


def _add_replace_args(parser):
    parser.add_argument(
        '--shards_account_prefix', metavar='shards_account_prefix', type=str,
        required=False, default='.shards_',
        help="Prefix for shards account. The default is '.shards_'. This "
             "should only be changed if the auto_create_account_prefix option "
             "has been similarly changed in swift.conf.")
    parser.add_argument(
        '--replace-timeout', type=int, default=600,
        help='Minimum DB timeout to use when replacing shard ranges.')
    parser.add_argument(
        '--force', '-f', action='store_true', default=False,
        help='Delete existing shard ranges; no questions asked.')
    parser.add_argument(
        '--enable', action='store_true', default=False,
        help='Enable sharding after adding shard ranges.')


def _add_enable_args(parser):
    parser.add_argument(
        '--enable-timeout', type=int, default=300,
        help='DB timeout to use when enabling sharding.')


def _add_prompt_args(parser):
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        '--yes', '-y', action='store_true', default=False,
        help='Apply shard range changes to broker without prompting. '
             'Cannot be used with --dry-run option.')
    group.add_argument(
        '--dry-run', '-n', action='store_true', default=False,
        help='Do not apply any shard range changes to broker. '
             'Cannot be used with --yes option.')


def _make_parser():
    parser = argparse.ArgumentParser(description='Manage shard ranges')
    parser.add_argument('path_to_file',
                        help='Path to a container DB file or, for the analyze '
                        'subcommand, a shard data file.')
    parser.add_argument('--config', dest='conf_file', required=False,
                        help='Path to config file with [container-sharder] '
                             'section. The following subcommand options will '
                             'be loaded from a config file if they are not '
                             'given on the command line: '
                             'rows_per_shard, '
                             'max_shrinking, '
                             'max_expanding, '
                             'shrink_threshold, '
                             'expansion_limit')
    parser.add_argument('--verbose', '-v', action='count', default=0,
                        help='Increase output verbosity')
    # this is useful for probe tests that shard containers with unrealistically
    # low numbers of objects, of which a significant proportion may still be in
    # the pending file
    parser.add_argument(
        '--force-commits', action='store_true', default=False,
        help='Force broker to commit pending object updates before finding '
             'shard ranges. By default the broker will skip commits.')
    subparsers = parser.add_subparsers(
        dest='subcommand', help='Sub-command help', title='Sub-commands')

    # find
    find_parser = subparsers.add_parser(
        'find', help='Find and display shard ranges')
    _add_find_args(find_parser)
    find_parser.set_defaults(func=find_ranges)

    # delete
    delete_parser = subparsers.add_parser(
        'delete', help='Delete all existing shard ranges from db')
    delete_parser.add_argument(
        '--force', '-f', action='store_true', default=False,
        help='Delete existing shard ranges; no questions asked.')
    delete_parser.set_defaults(func=delete_shard_ranges)

    # show
    show_parser = subparsers.add_parser(
        'show', help='Print shard range data')
    show_parser.add_argument(
        '--include_deleted', '-d', action='store_true', default=False,
        help='Include deleted shard ranges in output.')
    show_parser.add_argument(
        '--brief', '-b', action='store_true', default=False,
        help='Show only shard range bounds in output.')
    show_parser.add_argument('--includes',
                             help='limit shard ranges to include key')
    show_parser.set_defaults(func=show_shard_ranges)

    # info
    info_parser = subparsers.add_parser(
        'info', help='Print container db info')
    info_parser.set_defaults(func=db_info)

    # replace
    replace_parser = subparsers.add_parser(
        'replace',
        help='Replace existing shard ranges. User will be prompted before '
             'deleting any existing shard ranges.')
    replace_parser.add_argument('input', metavar='input_file',
                                type=str, help='Name of file')
    _add_replace_args(replace_parser)
    replace_parser.set_defaults(func=replace_shard_ranges)

    # find_and_replace
    find_replace_parser = subparsers.add_parser(
        'find_and_replace',
        help='Find new shard ranges and replace existing shard ranges. '
             'User will be prompted before deleting any existing shard ranges.'
    )
    _add_find_args(find_replace_parser)
    _add_replace_args(find_replace_parser)
    _add_enable_args(find_replace_parser)
    find_replace_parser.set_defaults(func=find_replace_shard_ranges)

    # enable
    enable_parser = subparsers.add_parser(
        'enable', help='Enable sharding and move db to sharding state.')
    _add_enable_args(enable_parser)
    enable_parser.set_defaults(func=enable_sharding)
    _add_replace_args(enable_parser)

    # compact
    compact_parser = subparsers.add_parser(
        'compact',
        help='Compact shard ranges with less than the shrink-threshold number '
             'of rows. This command only works on root containers.')
    _add_prompt_args(compact_parser)
    compact_parser.add_argument(
        '--shrink-threshold', nargs='?', type=_positive_int,
        default=USE_SHARDER_DEFAULT,
        help='The number of rows below which a shard can qualify for '
             'shrinking. '
             'Defaults to %d' % DEFAULT_SHARDER_CONF['shrink_threshold'])
    compact_parser.add_argument(
        '--expansion-limit', nargs='?', type=_positive_int,
        default=USE_SHARDER_DEFAULT,
        help='Maximum number of rows for an expanding shard to have after '
             'compaction has completed. '
             'Defaults to %d' % DEFAULT_SHARDER_CONF['expansion_limit'])
    # If just one donor shard is chosen to shrink to an acceptor then the
    # expanded acceptor will handle object listings as soon as the donor shard
    # has shrunk. If more than one donor shard are chosen to shrink to an
    # acceptor then the acceptor may not handle object listings for some donor
    # shards that have shrunk until *all* donors have shrunk, resulting in
    # temporary gap(s) in object listings where the shrunk donors are missing.
    compact_parser.add_argument('--max-shrinking', nargs='?',
                                type=_positive_int,
                                default=USE_SHARDER_DEFAULT,
                                help='Maximum number of shards that should be '
                                     'shrunk into each expanding shard. '
                                     'Defaults to 1. Using values greater '
                                     'than 1 may result in temporary gaps in '
                                     'object listings until all selected '
                                     'shards have shrunk.')
    compact_parser.add_argument('--max-expanding', nargs='?',
                                type=_positive_int,
                                default=USE_SHARDER_DEFAULT,
                                help='Maximum number of shards that should be '
                                     'expanded. Defaults to unlimited.')
    compact_parser.set_defaults(func=compact_shard_ranges)

    # repair
    repair_parser = subparsers.add_parser(
        'repair',
        help='Repair overlapping shard ranges. No action will be taken '
             'without user confirmation unless the -y option is used.')
    _add_prompt_args(repair_parser)
    repair_parser.set_defaults(func=repair_shard_ranges)

    # analyze
    analyze_parser = subparsers.add_parser(
        'analyze',
        help='Analyze shard range json data read from file. Use -v to see '
             'more detailed analysis.')
    analyze_parser.set_defaults(func=analyze_shard_ranges)

    return parser


def main(cli_args=None):
    parser = _make_parser()
    args = parser.parse_args(cli_args)
    if not args.subcommand:
        # On py2, subparsers are required; on py3 they are not; see
        # https://bugs.python.org/issue9253. py37 added a `required` kwarg
        # to let you control it, but prior to that, there was no choice in
        # the matter. So, check whether the destination was set and bomb
        # out if not.
        parser.print_help()
        print('\nA sub-command is required.', file=sys.stderr)
        return EXIT_INVALID_ARGS

    try:
        conf = {}
        if args.conf_file:
            conf = readconf(args.conf_file, 'container-sharder')
        conf.update(dict((k, v) for k, v in vars(args).items()
                         if v != USE_SHARDER_DEFAULT))
        conf_args = ContainerSharderConf(conf)
    except (OSError, IOError) as exc:
        print('Error opening config file %s: %s' % (args.conf_file, exc),
              file=sys.stderr)
        return EXIT_ERROR
    except (TypeError, ValueError) as exc:
        print('Error loading config: %s' % exc, file=sys.stderr)
        return EXIT_INVALID_ARGS

    for k, v in vars(args).items():
        # set any un-set cli args from conf_args
        if v is USE_SHARDER_DEFAULT:
            setattr(args, k, getattr(conf_args, k))

    if args.func in (analyze_shard_ranges,):
        args.input = args.path_to_file
        return args.func(args) or 0

    logger = get_logger({}, name='ContainerBroker', log_to_console=True)
    broker = ContainerBroker(os.path.realpath(args.path_to_file),
                             logger=logger,
                             skip_commits=not args.force_commits)
    try:
        broker.get_info()
    except Exception as exc:
        print('Error opening container DB %s: %s' % (args.path_to_file, exc),
              file=sys.stderr)
        return EXIT_ERROR
    print('Loaded db broker for %s' % broker.path, file=sys.stderr)
    return args.func(broker, args)


if __name__ == '__main__':
    exit(main())
