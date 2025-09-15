#include <concepts>
#include <utility>
#include <vector>
#include <iostream>

// TODO Include the bloom filter headers
template <class BF>
concept BloomFilterType = requires(BF bf) {
  { bf.Insert(uint32_t{}, uint32_t{}) } -> std::same_as<void>;
  { bf.Query(uint32_t{}, uint32_t{}) } -> std::same_as<bool>;
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
    std::vector<std::string> filter_names = 
    {...};
 //TODO run the benchmarks   
}