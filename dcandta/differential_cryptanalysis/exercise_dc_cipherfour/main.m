% authors:      Pjotr Piet, Stefano jonjic
% university:   UvA
% course:       Introduction to security
% student id's: 12714933, 13237594

% Differential Cryptanalysis on CipherFour
clear all;
close all;

% Generate a few thousand 16-bit plaintexts pairs
% Each plaintext can be organized as 4 nibbles: [a b c d]
% Note that a nibble is a 4-bit value
% Ensure that the difference between every plaintext pair (m0,m1) is
% equal to (0 0 2 0)
% initiate the
no_pairs = 2000;
delta = [0 0 2 0];

% initiate the empty arrays
m0s = zeros(no_pairs, 4);
m1s = zeros(no_pairs, 4);

% for the number of pairs
for i=1:no_pairs
    % create 4 random 4-bit values for m0
    a0 = randi([0 15], 1, 1);
    b0 = randi([0 15], 1, 1);
    c0 = randi([0 15], 1, 1);
    d0 = randi([0 15], 1, 1);

    % create 4 4-bit values for m1 so the difference is (0 0 2 0)
    a1 = bitxor(delta(1), a0);
    b1 = bitxor(delta(2), b0);
    c1 = bitxor(delta(3), c0);
    d1 = bitxor(delta(4), d0);

    % add the nibbles together
    m0 = [a0 b0 c0 d0];
    m1 = [a1 b1 c1 d1];

    % store the plaintexts in the array
    m0s(i, :) = m0;
    m1s(i, :) = m1;
end

% initiate the empty ciphertexts that we'll be using
c0s = [];
c1s = [];

% for all generated plaintext pairs
for i=1:no_pairs
    % compute the respective ciphertext pairs using the cipher_four()
    % implementation
    m0 = m0s(i, :);
    m1 = m1s(i, :);

    c0 = cipher_four(m0);
    c1 = cipher_four(m1);

    % apply filtering to the ciphertext pairs i.e.
    % -compute the difference between the ciphertext pairs
    delta_c = bitxor(c0, c1);

    % -check if this difference could be originating from a correct pair
    % the correct pairs are: (0 0 h 0) where h is in {1,2,9,10}
    if all(delta_c == [0 0 1 0]) || all(delta_c == [0 0 2 0]) || ...
           all(delta_c == [0 0 9 0]) || all(delta_c == [0 0 10 0])

    % -if the ciphertext pair passes the filter's check, we keep it
    % otherwise, we discard it
        c0s = [c0s; c0];
        c1s = [c1s; c1];
    end


end

% focus on the 3rd nibble of the ciphertext pairs that were kept after
% filtering

% initalize the counter for all key candidates to zero
key_counter = zeros(1, 16);

% for all ciphertexts that remain after filtering
for i=1:size(c0s)

    % for all key guesses of the 3rd nible of roundkey k6
    for key_guess=0:15

        % invert the 6th addkey operation
        r0 = bitxor(key_guess, c0s(i, 3));
        r1 = bitxor(key_guess, c1s(i, 3));

        % invert the sbox
        q0 = inv_sbox(r0);
        q1 = inv_sbox(r1);

        % compute the difference delta
        delta_q = bitxor(q0, q1);

        % compare the delta with the difference (0 0 2 0)
        % if they are equal then increment the the respective key counter
        % by one
        if delta_q == 2
            key_counter(key_guess+1) = key_counter(key_guess+1) + 1;
        end
    end

end

% find which key guess has the largest counter
[max_val, max_index] = max(key_counter);

% print and store the recovered key nibble
k6_recovered = max_index - 1;
disp(k6_recovered);

% you can also confirm by comparing it to the correct key nibble in
% cipher_four()
k6_recovered == 12;

% visualize with a bar plot the counters for the k6 key guesses
bar(0:15, key_counter);
