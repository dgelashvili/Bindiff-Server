#include "NeighbourhoodMatcher.h"

void NeighbourhoodMatcher::match(
	const std::shared_ptr<BinExportContent> &primary,
	const std::shared_ptr<BinExportContent> &secondary,
	std::vector<Match> &out_matches,
	std::vector<PotentialMatches> &unmatched_groups) const {

	std::set<int> primary_matched_indices, secondary_matched_indices;
	std::vector<std::pair<int, int>> matching_indices;
	for (const auto& match : out_matches) {
		int primary_index = primary->get_index_from_address(match.address_primary);
		int secondary_index = secondary->get_index_from_address(match.address_secondary);

		primary_matched_indices.insert(primary_index);
		secondary_matched_indices.insert(secondary_index);
		matching_indices.push_back(std::make_pair(primary_index, secondary_index));
	}

	PotentialMatches merged_unmatched_groups;
	for (const auto& potential_matches : unmatched_groups) {
		for (const auto& index : potential_matches.primary) {
			merged_unmatched_groups.primary.push_back(index);
		}
		for (const auto& index : potential_matches.secondary) {
			merged_unmatched_groups.secondary.push_back(index);
		}
	}

	std::map<std::pair<int, int>, std::pair<int, int>> neighbour_score;

	fill_neighbour_score(
		neighbour_score,
		primary,
		secondary,
		primary_matched_indices,
		secondary_matched_indices,
		matching_indices);

	std::unordered_map<int, std::vector<int>> primary_to_secondary;
	std::unordered_map<int, std::vector<int>> secondary_to_primary;
	fill_potential_matches(
		primary,
		secondary,
		primary_to_secondary,
		secondary_to_primary,
		neighbour_score);

	std::set<int> newly_matched_primary, newly_matched_secondary;
	for (const auto& [primary_index, possible_matches] : primary_to_secondary) {
		if (possible_matches.size() > 1) continue;
		int secondary_index = primary_to_secondary[primary_index][0];
		if (secondary_to_primary[secondary_index].size() == 1) {
			Match match;
			match.address_primary = primary->get_functions()[primary_index].get_address();
			match.address_secondary = secondary->get_functions()[secondary_index].get_address();
			match.similarity = 1;
			match.confidence = 1;
			out_matches.push_back(match);

			newly_matched_primary.insert(primary_index);
			newly_matched_secondary.insert(secondary_index);
		}
	}

	PotentialMatches new_potential_matches;
	for (const auto& index : merged_unmatched_groups.primary) {
		if (newly_matched_primary.find(index) == newly_matched_primary.end()) {
			new_potential_matches.primary.push_back(index);
		}
	}
	for (const auto& index : merged_unmatched_groups.secondary) {
		if (newly_matched_secondary.find(index) == newly_matched_secondary.end()) {
			new_potential_matches.secondary.push_back(index);
		}
	}

	unmatched_groups.clear();
	unmatched_groups.push_back(std::move(new_potential_matches));
}

void NeighbourhoodMatcher::fill_neighbour_score(
	std::map<std::pair<int, int>, std::pair<int, int>> &neighbour_score,
	const std::shared_ptr<BinExportContent> &primary,
	const std::shared_ptr<BinExportContent> &secondary,
	std::set<int> &primary_matched_indices,
	std::set<int> &secondary_matched_indices,
	std::vector<std::pair<int, int>> &matching_indices) {

	for (const auto& match : matching_indices) {
		std::vector<int> primary_caller_neighbours = primary->get_caller_neighbours(match.first);
		std::vector<int> secondary_caller_neighbours = secondary->get_caller_neighbours(match.second);

		for (const auto& primary_index: primary_caller_neighbours) {
			if (primary_matched_indices.find(primary_index) != primary_matched_indices.end()) {
				continue;
			}
			for (const auto& secondary_index: secondary_caller_neighbours) {
				if (secondary_matched_indices.find(secondary_index) != secondary_matched_indices.end()) {
					continue;
				}

				neighbour_score[std::make_pair(primary_index, secondary_index)].first++;
			}
		}

		std::vector<int> primary_callee_neighbours = primary->get_callee_neighbours(match.first);
		std::vector<int> secondary_callee_neighbours = secondary->get_callee_neighbours(match.second);

		for (const auto& primary_index: primary_callee_neighbours) {
			if (primary_matched_indices.find(primary_index) != primary_matched_indices.end()) {
				continue;
			}
			for (const auto& secondary_index: secondary_callee_neighbours) {
				if (secondary_matched_indices.find(secondary_index) != secondary_matched_indices.end()) {
					continue;
				}

				neighbour_score[std::make_pair(primary_index, secondary_index)].second++;
			}
		}
	}
}

void NeighbourhoodMatcher::fill_potential_matches(
	const std::shared_ptr<BinExportContent> &primary,
	const std::shared_ptr<BinExportContent> &secondary,
	std::unordered_map<int, std::vector<int>> &primary_to_secondary,
	std::unordered_map<int, std::vector<int>> &secondary_to_primary,
	std::map<std::pair<int, int>, std::pair<int, int>> &neighbour_score) {

	constexpr double THRESHOLD = 0.75;

	for (const auto& [pair, score] : neighbour_score) {
		const int primary_index = pair.first;
		const int secondary_index = pair.second;
		const double primary_out_score =
			(int) primary->get_callee_neighbours(primary_index).size() ?
				(double) score.first / (int) primary->get_callee_neighbours(primary_index).size() : 1.0;
		const double secondary_out_score =
			(int) secondary->get_callee_neighbours(secondary_index).size() ?
				(double) score.first / (int) secondary->get_callee_neighbours(secondary_index).size() : 1.0;
		const double primary_in_score =
			(int) primary->get_caller_neighbours(primary_index).size() ?
				(double) score.second / (int) primary->get_caller_neighbours(primary_index).size() : 1.0;
		const double secondary_in_score =
			(int) secondary->get_caller_neighbours(secondary_index).size() ?
				(double) score.second / (int) secondary->get_caller_neighbours(secondary_index).size() : 1.0;

		if (primary_out_score >= THRESHOLD &&
			secondary_out_score >= THRESHOLD &&
			primary_in_score >= THRESHOLD &&
			secondary_in_score >= THRESHOLD) {
			primary_to_secondary[primary_index].push_back(secondary_index);
			secondary_to_primary[secondary_index].push_back(primary_index);
		}
	}
}
