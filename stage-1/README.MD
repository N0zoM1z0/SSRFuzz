My own implementation of stage-1 in SSRFuzz.

1. Prepare PHP manual / document
2. LLM generate PoCs(simple php using correct API)
3. Replace the $args of the API generated in step-2
4. Evaluate php file
5. CBServer detect -> Right / Wrong

