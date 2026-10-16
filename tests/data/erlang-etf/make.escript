#!/usr/bin/env escript
%% Writes the erlang-etf fixtures (see make.sh) with term_to_binary/2.
%% Every term is fixed except the pid, port and reference, whose node name
%% is the container's (nonode@nohost when not distributed) and whose
%% numbers depend on the runtime's state.
main([Dir]) ->
    Big = 1 bsl 100,
    Huge = -(1 bsl 2100),
    Fun = fun(X) -> X + 1 end,
    Term = #{
        small => 42,
        negative => -7,
        int => 123456789,
        big => Big,
        huge_negative => Huge,
        float => 3.14159,
        atom => 'fillyfoal',
        utf8_atom => 'žolna',
        empty => [],
        string => "hello",
        list => [1, two, <<"three">>, 4.0],
        improper => [a | b],
        tuple => {point, 1, 2},
        large_tuple => list_to_tuple(lists:seq(1, 300)),
        binary => <<"bytes", 0, 1, 2>>,
        bits => <<5:3>>,
        nested => #{inner => [#{deep => {ok}}]},
        unicode => <<"čaj"/utf8>>,
        pid => self(),
        port => hd(erlang:ports()),
        ref => make_ref(),
        export => fun lists:map/2,
        local_fun => Fun,
        true_ => true
    },
    ok = file:write_file(filename:join(Dir, "terms.etf"), term_to_binary(Term)),
    %% minor_version 1: Latin-1 atoms (ATOM_EXT/SMALL_ATOM_EXT) where they fit
    Plain = [alpha, 'beta gamma', {1.5, -2}, "text", <<"bin">>],
    ok = file:write_file(filename:join(Dir, "latin1.etf"),
                         term_to_binary(Plain, [{minor_version, 1}])),
    %% minor_version 0: floats as 31-byte text (FLOAT_EXT)
    ok = file:write_file(filename:join(Dir, "old-float.etf"),
                         term_to_binary([2.5, -0.125], [{minor_version, 0}])),
    %% compressed (COMPRESSED, zlib)
    Repeated = lists:duplicate(200, {record, <<"repeated payload">>, 12345}),
    ok = file:write_file(filename:join(Dir, "compressed.etf"),
                         term_to_binary(Repeated, [compressed])),
    io:format("~s~n", [erlang:system_info(otp_release)]).
