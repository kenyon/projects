primes :: [Int]
primes = sieve [2..]
sieve (x:xs) = x : sieve [y | y <- xs, (y `rem` x) /= 0]

memberOrd :: Ord a => [a] -> a -> Bool
memberOrd (x:xs) n
    | x < n = memberOrd xs n
    | x == n = True
    | otherwise = False

isPrime n = memberOrd primes n
