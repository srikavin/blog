import React, {Component} from 'react';
import {PostStore} from '../../data/resource/post';
import PostList from './PostList/PostList';

class PostPreviews extends Component {
    constructor(props) {
        super(props);
        this.state = {
            posts: []
        };
    }

    componentDidMount() {
        PostStore.getAll().then(e => {
            this.setState({
                posts: e
            });
        }).catch(console.error);
    }

    render() {
        return (
            <PostList posts={this.state.posts}/>
        );
    }
}

export default PostPreviews;