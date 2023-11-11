% authors:      Pjotr Piet, Stefano jonjic
% university:   UvA
% course:       Introduction to security
% student id's: 12714933, 13237594
clear all;
close all;


% load the plaintext, the time measurements and the server
% key used during the profiling phase
load("profile_measurement_and_plaintext_and_key.mat");

% load the plaintext and the time measurements
% used during the attack phase
load("attack_measurement_and_plaintext.mat");

% initiate the array for the different plaintexts
m = max(plaintext_profile);
groups = zeros(m, 2);

% create an 256x1 array to store all the time measurements according to
% their corresponding plaintext values
measurements = zeros(m + 1, 1);

% loop over all plaintexts
for plaintext=0:m

    % initiate the measurements variable
    measurements = [];
    % loop over all measurements that we have
    for i=1:size(plaintext_profile)


        % when we find the current plaintext, add the value to measurements
        if plaintext == plaintext_profile(i)
            measurements(end+1) = time_measurement_profile(i);
        end

    end

    % compute every groups average and standard deviation
    groups(plaintext+1, 1) = mean(measurements);
    groups(plaintext+1, 2) = std(measurements);

end


% Compute the total mean of all groups
totalMean = mean(groups(:, 1));

% initiate the array to store the delta means per group
deltas = zeros(m+1, 1);

% loop over all plaintexts
for i=1:m+1

    % compute the difference between current group mean and total mean
    deltas(i) = groups(i, 1) - totalMean;
end


% Find the plaintext value that maximizes the difference delta (profile
% phase)
[~, pmax] = max(deltas);
pmax = pmax-1;

% We have the plaintext that maximizes the execution time. Since the server
% is a profile server, its key is also known
% Thus we compute which LUT index maximizes the execution time
amax = bitxor(pmax, k_profile);


% Using the attack measurements we will again recover the plaintext that
% when XORed with the server key results in the LUT index that maximizes
% the execution time

% initiate the array for the different plaintexts
m = max(plaintext_attack);
groups_attack = zeros(m, 2);

% create an 256x1 array to store all the time measurements according to
% their corresponding plaintext values
measurements = zeros(m+1, 1);

% loop over all plaintexts
for plaintext=0:m

    % initiate the measurements variable
    measurements = [];
    % loop over all measurements that we have
    for i=1:size(plaintext_attack)

        % when we find the current plaintext, add the value to measurements
        if plaintext == plaintext_attack(i)
            measurements(end+1) = time_measurement_attack(i);
        end

    end

    % compute every groups average and standard deviation
    groups_attack(plaintext+1, 1) = mean(measurements);
    groups_attack(plaintext+1, 2) = std(measurements);

end

% Compute the total mean of all groups
totalMean = mean(groups_attack(:, 1));

% initiate the array to store the delta means per group
deltas = zeros(m+1, 1);

% loop over all plaintexts
for i=1:m+1

    % compute the difference between current group mean and total mean
    deltas(i) = groups_attack(i, 1) - totalMean;
end

% Find the plaintext value that maximizes the difference delta (attack
% phase)
[dmax, pmax] = max(deltas);
pmax = pmax-1;

% We know already from the profiling phase the LUT index that maximizes the
% attack time. We have also recovered from the attack phase the plaintext
% that, once XORed with the unknown key, will result in this LUT index.
unknown_key = bitxor(amax, pmax);  % we get the value 101 for the uncovered key
disp(unknown_key);
