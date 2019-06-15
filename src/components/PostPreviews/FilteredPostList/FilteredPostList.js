import React, {Component} from 'react';
import {PostStore} from '../../../data/resource/post';
import PostList from '../PostList/PostList';
import {TagStore} from '../../../data/resource/tag';

import PropTypes from 'prop-types';
import ItemSelector from './ItemSelector/ItemSelector'

import styles from './FilteredPostList.module.css'
import {debounce} from "../../util/debounce";

class FilteredPostList extends Component {
    updatePosts = debounce(200, function () {
        let tagIds = this.state.filter.map(e => e.id);
        PostStore.query({
            tags: tagIds,
            search: this.state.search
        }).then(e => {
            this.setState({
                posts: e
            });
        }).catch(console.error);
        if (tagIds.length > 0) {
            this.props.history.push(`/blog/tag/${tagIds.join(',')}`)
        }
    });

    constructor(props) {
        super(props);
        let tags = [];

        this.state = {
            tags: tags,
            loading: true,
            filter: [],
            search: ''
        };

        TagStore.getAll().then((tags) => {
            this.setState({
                tags,
                loading: false
            });
        });

        this.changeTagFilter = this.changeTagFilter.bind(this);
        this.updatePosts = this.updatePosts.bind(this);
        this.changeSearch = this.changeSearch.bind(this);

        this.updatePosts();
    }

    componentDidMount() {
        let query = this.props.match.params;
        if (query.tags) {
            let tags = query.tags.split(',');
            let p = [];
            tags.forEach(e => {
                p.push(TagStore.getById(e));
            });

            Promise.all(p).then((tags) => {
                console.log(tags);
                this.setState({
                    filter: tags
                }, this.updatePosts())
            });

        }
    }

    changeSearch(e) {
        this.setState({search: e.target.value}, this.updatePosts);
    }

    changeTagFilter(tags) {
        this.setState({
            filter: tags ? tags : []
        }, this.updatePosts);
    }

    render() {
        return (
            <>
                <div className={styles.filters}>
                    <span className={styles.filterText}>Filters: </span>
                    <div className={styles.filter}>
                        <input className={styles.search} type={"text"} placeholder={"Search"} value={this.state.search}
                               onChange={this.changeSearch}/>
                    </div>
                    <ItemSelector tags={this.state.tags}
                                  loading={this.state.loading}
                                  placeholder={"Tags"}
                                  value={this.state.filter}
                                  className={styles.filter}
                                  onChange={this.changeTagFilter}/>
                </div>
                <PostList posts={this.state.posts}/>
            </>
        );
    }
}


FilteredPostList.propTypes = {
    query: PropTypes.any,
    filter: PropTypes.func
};

export default FilteredPostList;