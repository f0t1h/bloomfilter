#include <concepts>
#include <utility>
#include <vector>
#include <iostream>
#include <unordered_set>
#include <fstream>
#include <algorithm>
#include <random>

// TODO Include the bloom filter headers
template <class BF>
concept BloomFilterType = requires(BF bf) {
  { bf.Insert(uint32_t{}, uint32_t{}) } -> std::same_as<void>;
  { bf.Query(uint32_t{}, uint32_t{}) } -> std::same_as<bool>;
  { bf.TotalBitsUsed() } -> std::same_as<size_t>;
};


struct unordered_set_baseline {
  std::unordered_set<std::pair<uint32_t, uint32_t>> set;
  void Insert(uint32_t h1, uint32_t h2) {
    set.insert({h1, h2});
  }
  bool Query(uint32_t h1, uint32_t h2) {
    return set.find({h1, h2}) != set.end();
  }
  size_t TotalBitsUsed() const {
    return set.bucket_count() * set.max_load_factor() * sizeof(std::pair<uint32_t, uint32_t>) * 8;
  }
};

struct BenchmarkDataPoint {
  std::string filter_name;
  int threads;
  double insert_time;
  double query_time;
  double false_positive_rate;
  double false_negative_rate;
  size_t number_of_bits;
  size_t insert_count;
  size_t query_count;
  friend std::ostream& operator<<(std::ostream& os, const BenchmarkDataPoint& data) {
    os << data.filter_name << "\t" << data.threads << "\t" << data.insert_time << "\t" << data.query_time << "\t" << data.false_positive_rate << "\t" << data.false_negative_rate << "\t" << data.number_of_bits << "\t" << data.insert_count << "\t" << data.query_count;
    return os;
  }

};

template <BloomFilterType BF> struct BloomBenchmark {
  BF filter;
  int threads;
  BloomBenchmark(BF &&bf, int threads)
      : filter(std::move(bf)), threads(threads) {}
  auto run(const std::vector<std::pair<uint32_t, uint32_t>> &true_data,
           const std::vector<std::pair<uint32_t, uint32_t>> &false_data)
      -> BenchmarkDataPoint {
        //TODO implement the benchmark
      }
};

int main(int argc, char** argv) {
    std::vector<int> threads = {1, 4, 8, 16};
    int insertions = 100000;
    int queries = 100000;
    std::vector<std::string> filter_names = 
    {...};
    std::ifstream inputFile;
    inputFile.open("whitelist/3M-february-2018.txt", std::ifstream::in);
    std::vector<std::string> whitelist;
    while (!inputFile.eof()) {
        std::string line;
        std::getline(inputFile, line);
        whitelist.push_back(line);
    }
    inputFile.close();

    // generate insert_data and query_data randomly from whitelist
    std::vector<std::string> insert_data;
    std::vector<std::string> query_data;
    auto rng = std::default_random_engine(42);
    std::shuffle(std::begin(whitelist), std::end(whitelist), rng);
    insert_data = std::vector<std::string>(whitelist.begin(), whitelist.begin() + insertions);
    query_data = std::vector<std::string>(whitelist.begin() + insertions, whitelist.begin() + insertions + queries);

    return 0;
}   