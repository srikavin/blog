import React, {Component} from 'react';
import PostSnippet from './PostSnippet/PostSnippet';
import PropTypes from 'prop-types';
import styles from './PostList.module.css'

class PostList extends Component {
    render() {
        return (
            <div className={styles.container}>
                {this.props.posts.map(e => <PostSnippet className={styles.preview} key={e.slug} post={e}/>)}
            </div>
        );
    }
}

PostList.propTypes = {
    posts: PropTypes.array.isRequired
};

export default PostList;