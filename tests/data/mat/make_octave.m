% Writes tests/fixtures/external/mat/octave-v7.mat with GNU Octave
% (MAT-file Level 5, every variable compressed). See SOURCES.md for the
% docker command; the creation time in the header text is pinned
% afterwards by make_octave.sh.
x = reshape(0:5, 2, 3);
u8 = uint8([7 0 8 0 0 9]);
flag = logical([1 0 0 1]);
greeting = 'hello';
st.a = 1.5;
st.b = 'hi';
c = {3.5, int16([1 0 2])};
sp = sparse([0 2 0; 1 0 3]);
save('-v7', 'octave-v7.mat', 'x', 'u8', 'flag', 'greeting', 'st', 'c', 'sp');
save('-v6', 'octave-v6.mat', 'x', 'u8', 'flag', 'greeting', 'st', 'c', 'sp');
