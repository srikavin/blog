import React, {Component, Fragment} from 'react';
import {PostStore} from '../../../data/resource/post';
import PostList from '../PostList/PostList';
import {TagStore} from '../../../data/resource/tag';

import PropTypes from 'prop-types';
import TagEditor from '../../PostEditor/TagEditor/TagEditor';

class FilteredPostList extends Component {
    constructor(props) {
        super(props);
        let query = this.props.match.params;
        if (query.tags) {
            query.tags = query.tags.split(',')
        }
        this.state = {
            posts: [],
            query: query,
            filter: []
        };
        this.changeTagFilter = this.changeTagFilter.bind(this);
    }

    componentDidMount() {
        let query = this.state.query;
        PostStore.query(query).then(e => {
            this.setState({
                posts: e
            });
        }).catch(console.error);

        if (query.tags) {
            query.tags.forEach(e => {
                TagStore.getById(e).then(res => {
                    this.setState({
                        filter: [...this.state.filter, res]
                    });
                })
            })
        }
    }

    changeTagFilter(tags) {
        let query = this.state.query;
        query.tags.push(tags);
        this.setState({
            query
        })
    }

    render() {
        return (
            <Fragment>
                Filtering on: <TagEditor onSelectedChange={this.changeTagFilter} tags={this.state.query.tags}/>
                <PostList posts={this.state.posts}/>
            </Fragment>
        );
    }
}


FilteredPostList.propTypes = {
    query: PropTypes.any,
    filter: PropTypes.func
};

export default FilteredPostList;