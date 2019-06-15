import React, {Component} from 'react';
import PostSnippet from './PostSnippet/PostSnippet';
import PropTypes from 'prop-types';
import styles from './PostList.module.css'

class PostList extends Component {
    render() {
        if (!this.props.posts) {
            return (
                <div className={styles.container}>
                    {[1, 2, 3, 4, 5, 6, 7].map(e => {
                        return (
                            <PostSnippet className={styles.preview} key={e}/>
                        );
                    })}
                </div>
            );
        }

        return (
            <div className={styles.container}>
                {this.props.posts.map(e => <PostSnippet className={styles.preview} key={e.slug} post={e}/>)}
            </div>
        );
    }
}

PostList.propTypes = {
    posts: PropTypes.array
};

export default PostList;